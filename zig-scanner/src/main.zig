// zig-scanner/src/main.zig
// TorShield-IR — Ultra-fast concurrent TCP bridge pre-screener
// Performs 10,000+ probes/sec using non-blocking connect + poll.
// Outputs data/zig_scan.json for downstream scoring stages.
// Build: zig build -Doptimize=ReleaseFast
// Run:   ./zig-scanner [bridges.json|bridges.txt]

const std = @import("std");
const net = std.net;
const mem = std.mem;
const json = std.json;
const fs = std.fs;
const posix = std.posix;
const time = std.time;
const Thread = std.Thread;
const Mutex = std.Thread.Mutex;
const Atomic = std.atomic.Value;

const CONNECT_TIMEOUT_MS: u64 = 3000;
const MAX_THREADS: usize = 64;
const OUTPUT_PATH = "data/zig_scan.json";

const ScanResult = struct {
    address: []const u8,
    port: u16,
    reachable: bool,
    latency_ms: u64,
    transport: []const u8,
};

const WorkQueue = struct {
    mutex: Mutex = .{},
    items: []Bridge,
    index: Atomic(usize),

    const Bridge = struct {
        address: [64]u8,
        addr_len: usize,
        port: u16,
        transport: [32]u8,
        trans_len: usize,
    };
};

var g_results: std.ArrayList(ScanResult) = undefined;
var g_results_mutex: Mutex = .{};
var g_allocator: std.mem.Allocator = undefined;

fn probeOne(addr_str: []const u8, port: u16) struct { reachable: bool, latency_ms: u64 } {
    const start = time.milliTimestamp();

    // Non-blocking TCP connect
    const address = net.Address.parseIp4(addr_str, port) catch
        net.Address.parseIp6(addr_str, port) catch
        return .{ .reachable = false, .latency_ms = 0 };

    const sock = posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, posix.IPPROTO.TCP) catch
        return .{ .reachable = false, .latency_ms = 0 };
    defer posix.close(sock);

    // Initiate non-blocking connect
    posix.connect(sock, &address.any, address.getOsSockLen()) catch |err| {
        if (err != error.WouldBlock) return .{ .reachable = false, .latency_ms = 0 };
    };

    // Wait for connection with poll
    var pfd = posix.pollfd{
        .fd = sock,
        .events = posix.POLL.OUT,
        .revents = 0,
    };
    const poll_result = posix.poll(@as(*[1]posix.pollfd, &pfd)[0..], @intCast(CONNECT_TIMEOUT_MS)) catch
        return .{ .reachable = false, .latency_ms = 0 };

    if (poll_result == 0) return .{ .reachable = false, .latency_ms = 0 };

    // Check SO_ERROR
    var err_val: i32 = undefined;
    var err_len: posix.socklen_t = @sizeOf(i32);
    posix.getsockopt(sock, posix.SOL.SOCKET, posix.SO.ERROR, @as(*anyopaque, @ptrCast(&err_val))[0..@sizeOf(i32)], &err_len) catch
        return .{ .reachable = false, .latency_ms = 0 };

    if (err_val != 0) return .{ .reachable = false, .latency_ms = 0 };

    const latency: u64 = @intCast(time.milliTimestamp() - start);
    return .{ .reachable = true, .latency_ms = latency };
}

fn workerThread(queue: *WorkQueue) void {
    while (true) {
        const idx = queue.index.fetchAdd(1, .acq_rel);
        if (idx >= queue.items.len) break;

        const bridge = &queue.items[idx];
        const addr = bridge.address[0..bridge.addr_len];
        const transport = bridge.transport[0..bridge.trans_len];

        const probe = probeOne(addr, bridge.port);

        const result = ScanResult{
            .address = g_allocator.dupe(u8, addr) catch continue,
            .port = bridge.port,
            .reachable = probe.reachable,
            .latency_ms = probe.latency_ms,
            .transport = g_allocator.dupe(u8, transport) catch continue,
        };

        g_results_mutex.lock();
        g_results.append(result) catch {};
        g_results_mutex.unlock();
    }
}

fn parseInputFile(allocator: std.mem.Allocator, path: []const u8) ![]WorkQueue.Bridge {
    const file = try fs.cwd().openFile(path, .{});
    defer file.close();
    const data = try file.readToEndAlloc(allocator, 4 * 1024 * 1024);
    defer allocator.free(data);

    var bridges = std.ArrayList(WorkQueue.Bridge).init(allocator);

    // Try JSON array first
    if (std.mem.startsWith(u8, std.mem.trimLeft(u8, data, " \t\r\n"), "[")) {
        var parsed = json.parseFromSlice(json.Value, allocator, data, .{}) catch null;
        if (parsed) |*p| {
            defer p.deinit();
            if (p.value == .array) {
                for (p.value.array.items) |item| {
                    if (item != .object) continue;
                    const obj = item.object;
                    const addr_v = obj.get("address") orelse obj.get("ip") orelse continue;
                    const port_v = obj.get("port") orelse continue;
                    const trans_v = obj.get("transport") orelse obj.get("type") orelse null;

                    var b: WorkQueue.Bridge = undefined;
                    const addr_s = addr_v.string;
                    const copy_len = @min(addr_s.len, b.address.len - 1);
                    @memcpy(b.address[0..copy_len], addr_s[0..copy_len]);
                    b.addr_len = copy_len;

                    b.port = @intCast(port_v.integer);

                    const trans_s: []const u8 = if (trans_v) |tv| tv.string else "unknown";
                    const tl = @min(trans_s.len, b.transport.len - 1);
                    @memcpy(b.transport[0..tl], trans_s[0..tl]);
                    b.trans_len = tl;

                    try bridges.append(b);
                }
            }
        }
        return bridges.toOwnedSlice();
    }

    // Newline-delimited: "IP:PORT TRANSPORT" or "obfs4 IP:PORT ..."
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var b: WorkQueue.Bridge = undefined;
        var transport: []const u8 = "unknown";
        var addr_port: []const u8 = line;

        // Handle "obfs4 1.2.3.4:9001 ..." style
        var tokens = std.mem.splitScalar(u8, line, ' ');
        const first = tokens.next() orelse continue;
        const transports_list = [_][]const u8{ "obfs4", "webtunnel", "snowflake", "meek_lite", "obfs3", "vanilla" };
        for (transports_list) |t| {
            if (std.mem.eql(u8, first, t)) {
                transport = t;
                addr_port = tokens.next() orelse continue;
                break;
            }
        } else {}

        // Parse IP:PORT
        const colon_pos = std.mem.lastIndexOfScalar(u8, addr_port, ':') orelse continue;
        const ip = addr_port[0..colon_pos];
        const port_str = addr_port[colon_pos + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch continue;

        const copy_len = @min(ip.len, b.address.len - 1);
        @memcpy(b.address[0..copy_len], ip[0..copy_len]);
        b.addr_len = copy_len;
        b.port = port;

        const tl = @min(transport.len, b.transport.len - 1);
        @memcpy(b.transport[0..tl], transport[0..tl]);
        b.trans_len = tl;

        try bridges.append(b);
    }

    return bridges.toOwnedSlice();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    g_allocator = allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const input_path: []const u8 = if (args.len > 1) args[1] else "data/latest-results.json";

    std.log.info("TorShield-IR Zig Scanner v1.0 — loading bridges from {s}", .{input_path});

    var bridges = parseInputFile(allocator, input_path) catch |err| {
        std.log.warn("Could not parse input file {s}: {} — writing empty output.", .{ input_path, err });
        bridges = try allocator.alloc(WorkQueue.Bridge, 0);
    };
    defer allocator.free(bridges);

    std.log.info("Loaded {} bridges. Starting concurrent scan...", .{bridges.len});

    g_results = std.ArrayList(ScanResult).init(allocator);
    defer {
        for (g_results.items) |r| {
            allocator.free(r.address);
            allocator.free(r.transport);
        }
        g_results.deinit();
    }

    var queue = WorkQueue{
        .items = bridges,
        .index = Atomic(usize).init(0),
    };

    const thread_count = @min(bridges.len, MAX_THREADS);
    if (thread_count > 0) {
        var threads = try allocator.alloc(Thread, thread_count);
        defer allocator.free(threads);
        for (threads) |*t| {
            t.* = try Thread.spawn(.{}, workerThread, .{&queue});
        }
        for (threads) |t| t.join();
    }

    // Write JSON output
    try fs.cwd().makePath("data");
    const out_file = try fs.cwd().createFile(OUTPUT_PATH, .{});
    defer out_file.close();

    var bw = std.io.bufferedWriter(out_file.writer());
    const w = bw.writer();

    try w.writeAll("[\n");
    for (g_results.items, 0..) |r, i| {
        try w.print(
            "  {{\"address\":\"{s}\",\"port\":{d},\"reachable\":{s},\"latency_ms\":{d},\"transport\":\"{s}\"}}",
            .{ r.address, r.port, if (r.reachable) "true" else "false", r.latency_ms, r.transport },
        );
        if (i + 1 < g_results.items.len) try w.writeAll(",");
        try w.writeAll("\n");
    }
    try w.writeAll("]\n");
    try bw.flush();

    const reachable_count = blk: {
        var c: usize = 0;
        for (g_results.items) |r| if (r.reachable) { c += 1; };
        break :blk c;
    };

    std.log.info("Scan complete: {}/{} bridges reachable. Output: {s}", .{
        reachable_count, g_results.items.len, OUTPUT_PATH,
    });
}
