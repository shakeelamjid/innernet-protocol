// A WebGPU test job: reads little-endian float32 numbers from standard input, doubles them on the
// GPU with a compute shader, and writes them back. "probe" reports what the sandbox allows.
const args = Deno.args;
if (args[0] === "probe") {
  const out = {};
  for (const [name, f] of [["files", () => Deno.readTextFile("/etc/hosts")], ["network", () => fetch("https://example.com")],
                           ["env", async () => Deno.env.get("HOME")], ["run", () => new Deno.Command("/bin/sh").output()]]) {
    try { await f(); out[name] = "open"; } catch (e) { out[name] = e.name; }
  }
  await Deno.stdout.write(new TextEncoder().encode(JSON.stringify(out)));
} else if (args[0] === "spin") {
  for (;;) {}
} else {
  const input = new Uint8Array(await new Response(Deno.stdin.readable).arrayBuffer());
  const data = new Float32Array(input.buffer, 0, input.byteLength / 4);
  const adapter = await navigator.gpu.requestAdapter();
  const device = await adapter.requestDevice();
  const module = device.createShaderModule({ code: `
    @group(0) @binding(0) var<storage, read_write> v: array<f32>;
    @compute @workgroup_size(64) fn main(@builtin(global_invocation_id) id: vec3<u32>) {
      if (id.x < arrayLength(&v)) { v[id.x] = v[id.x] * 2.0; }
    }` });
  const pipeline = device.createComputePipeline({ layout: "auto", compute: { module, entryPoint: "main" } });
  const buf = device.createBuffer({ size: data.byteLength, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST });
  device.queue.writeBuffer(buf, 0, data);
  const read = device.createBuffer({ size: data.byteLength, usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST });
  const bind = device.createBindGroup({ layout: pipeline.getBindGroupLayout(0), entries: [{ binding: 0, resource: { buffer: buf } }] });
  const enc = device.createCommandEncoder();
  const pass = enc.beginComputePass();
  pass.setPipeline(pipeline);
  pass.setBindGroup(0, bind);
  pass.dispatchWorkgroups(Math.ceil(data.length / 64));
  pass.end();
  enc.copyBufferToBuffer(buf, 0, read, 0, data.byteLength);
  device.queue.submit([enc.finish()]);
  await read.mapAsync(GPUMapMode.READ);
  await Deno.stdout.write(new Uint8Array(read.getMappedRange().slice(0)));
}
