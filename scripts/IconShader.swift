// Renders the iServer app icon with a Metal compute shader.
// Usage: swift scripts/IconShader.swift <output.png> [size]
import CoreGraphics
import Foundation
import ImageIO
import Metal
import UniformTypeIdentifiers

let shader = """
#include <metal_stdlib>
using namespace metal;

float hash(float2 p) { return fract(sin(dot(p, float2(127.1, 311.7))) * 43758.5453); }

float noise(float2 p) {
    float2 i = floor(p), f = fract(p);
    float2 u = f * f * (3.0 - 2.0 * f);
    return mix(mix(hash(i), hash(i + float2(1, 0)), u.x),
               mix(hash(i + float2(0, 1)), hash(i + float2(1, 1)), u.x), u.y);
}

float fbm(float2 p) {
    float v = 0.0, a = 0.5;
    for (int i = 0; i < 6; i++) { v += a * noise(p); p = p * 2.03 + float2(1.7, 9.2); a *= 0.5; }
    return v;
}

float sdRoundBox(float2 p, float2 b, float r) {
    float2 q = abs(p) - b + r;
    return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - r;
}

// macOS-style continuous-corner squircle (superellipse), radius 1 = full icon body.
float squircle(float2 p) {
    float2 a = abs(p);
    return pow(pow(a.x, 5.0) + pow(a.y, 5.0), 0.2) - 1.0;
}

float4 shade(float2 px, float size) {
    float s = size / 1024.0;
    float2 p = (px - 512.0 * s) / (412.0 * s);
    p.y = -p.y;
    float aa = 1.2 / (412.0 * s);

    // Drop shadow below the body.
    float shadow = (1.0 - smoothstep(-0.04, 0.16, squircle((p - float2(0.0, -0.035)) * 1.0))) * 0.5;

    float d = squircle(p);
    float body = 1.0 - smoothstep(-aa, aa, d);

    // Background: deep night gradient with an aurora band.
    float3 col = mix(float3(0.015, 0.018, 0.055), float3(0.085, 0.09, 0.20), smoothstep(-1.1, 1.0, p.y));
    float n = fbm(p * 1.7 + float2(0.0, 0.4));
    float wave = p.y - 0.18 * sin(p.x * 2.3 + n * 3.2) - 0.30;
    float band = exp(-pow(wave * 2.6, 2.0));
    float3 aurora = mix(float3(0.05, 0.95, 0.70), float3(0.55, 0.32, 1.0), smoothstep(-0.9, 0.9, p.x + (n - 0.5) * 1.4));
    col += band * aurora * (0.40 + 0.55 * n);
    float n2 = fbm(p * 3.5 - float2(2.0, 1.0));
    col += exp(-pow((p.y + 0.55 - 0.1 * sin(p.x * 3.0 + n2 * 4.0)) * 4.0, 2.0)) * float3(0.20, 0.25, 0.9) * 0.18;

    // Three glass rack units.
    float3 leds[3] = { float3(0.25, 1.0, 0.55), float3(0.25, 1.0, 0.55), float3(1.0, 0.45, 0.10) };
    float glow = 0.0;
    float3 glowCol = float3(0.0);
    for (int i = 0; i < 3; i++) {
        float2 c = float2(0.0, 0.44 - float(i) * 0.44);
        float2 q = p - c;
        float r = sdRoundBox(q, float2(0.64, 0.165), 0.085);
        float inside = 1.0 - smoothstep(-aa, aa, r);

        // Frosted glass fill, brighter towards the top edge.
        float3 glass = mix(col, float3(0.85, 0.90, 1.0), 0.09 + 0.13 * smoothstep(-0.17, 0.17, q.y));
        col = mix(col, glass, inside);
        // Rim light.
        float rim = exp(-abs(r) * 260.0) * (0.25 + 0.45 * smoothstep(-0.1, 0.15, q.y));
        col += rim * float3(0.85, 0.92, 1.0);

        // Drive-bay slots.
        for (int k = 0; k < 3; k++) {
            float slot = sdRoundBox(q - float2(0.19, 0.06 - float(k) * 0.06), float2(0.28, 0.016), 0.016);
            col = mix(col, float3(0.92, 0.95, 1.0), (1.0 - smoothstep(-aa, aa, slot)) * 0.22 * inside);
        }

        // Status LED with bloom.
        float2 lp = q - float2(-0.44, 0.0);
        float ld = length(lp);
        float core = 1.0 - smoothstep(0.062 - aa, 0.062 + aa, ld);
        float3 led = leds[i];
        col = mix(col, mix(led, float3(1.0), 0.55 * (1.0 - smoothstep(0.0, 0.05, length(lp - float2(-0.012, 0.014))))), core);
        float g = exp(-ld * 9.0);
        glow += g;
        glowCol += led * g;
    }
    col += glowCol * 0.75;

    // Top sheen and inner rim of the body.
    col += smoothstep(0.35, 1.05, p.y) * 0.05;
    col += exp(-abs(d) * 90.0) * smoothstep(-0.2, 1.0, p.y) * 0.18;

    // Film grain.
    col += (hash(px * 0.73) - 0.5) * 0.012;
    col = clamp(col, 0.0, 1.0);

    float alpha = body + shadow * (1.0 - body);
    return float4(col * body, alpha);  // premultiplied (shadow is black)
}

kernel void icon(texture2d<float, access::write> out [[texture(0)]],
                 constant float &size [[buffer(0)]],
                 uint2 gid [[thread_position_in_grid]]) {
    if (gid.x >= out.get_width() || gid.y >= out.get_height()) return;
    float4 acc = float4(0.0);
    const int SS = 4;
    for (int y = 0; y < SS; y++)
        for (int x = 0; x < SS; x++)
            acc += shade(float2(gid) + (float2(x, y) + 0.5) / float(SS), size);
    out.write(acc / float(SS * SS), gid);
}
"""

let args = CommandLine.arguments
guard args.count >= 2 else { print("usage: IconShader.swift <out.png> [size]"); exit(1) }
let size = args.count > 2 ? Int(args[2]) ?? 1024 : 1024

let device = MTLCreateSystemDefaultDevice()!
let library = try device.makeLibrary(source: shader, options: nil)
let pipeline = try device.makeComputePipelineState(function: library.makeFunction(name: "icon")!)

let desc = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .rgba8Unorm, width: size, height: size, mipmapped: false)
desc.usage = [.shaderWrite]
desc.storageMode = .shared
let texture = device.makeTexture(descriptor: desc)!

var fsize = Float(size)
let queue = device.makeCommandQueue()!
let cmd = queue.makeCommandBuffer()!
let enc = cmd.makeComputeCommandEncoder()!
enc.setComputePipelineState(pipeline)
enc.setTexture(texture, index: 0)
enc.setBytes(&fsize, length: MemoryLayout<Float>.size, index: 0)
enc.dispatchThreads(MTLSize(width: size, height: size, depth: 1),
                    threadsPerThreadgroup: MTLSize(width: 16, height: 16, depth: 1))
enc.endEncoding()
cmd.commit()
cmd.waitUntilCompleted()

var pixels = [UInt8](repeating: 0, count: size * size * 4)
texture.getBytes(&pixels, bytesPerRow: size * 4, from: MTLRegionMake2D(0, 0, size, size), mipmapLevel: 0)

let ctx = CGContext(data: &pixels, width: size, height: size, bitsPerComponent: 8, bytesPerRow: size * 4,
                    space: CGColorSpace(name: CGColorSpace.sRGB)!,
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
let dest = CGImageDestinationCreateWithURL(URL(fileURLWithPath: args[1]) as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(dest, ctx.makeImage()!, nil)
CGImageDestinationFinalize(dest)
print("Wrote \(args[1]) (\(size)×\(size))")
