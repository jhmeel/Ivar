package dev.ivar;

import com.dylibso.chicory.compiler.MachineFactoryCompiler;
import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.runtime.ImportValues;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.wasi.WasiOptions;
import com.dylibso.chicory.wasi.WasiPreview1;
import com.dylibso.chicory.wasm.Parser;
import com.dylibso.chicory.wasm.WasmModule;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;

/**
 * One WebAssembly instance of the verified decision core, compiled to JVM
 * bytecode by Chicory. Calls are serialised.
 */
public final class IvarRuntime {
    static final ObjectMapper JSON = new ObjectMapper();
    private static volatile IvarRuntime shared;

    private final Instance instance;
    private final ExportFunction alloc;
    private final ExportFunction free;
    private final ExportFunction call;

    public static IvarRuntime shared() {
        if (shared == null) {
            synchronized (IvarRuntime.class) {
                if (shared == null) shared = new IvarRuntime();
            }
        }
        return shared;
    }

    public IvarRuntime() {
        WasmModule module;
        try (InputStream in = IvarRuntime.class.getResourceAsStream("/ivar_core.wasm")) {
            if (in == null) throw new IllegalStateException("ivar_core.wasm missing from the classpath");
            module = Parser.parse(in.readAllBytes());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        WasiOptions options = WasiOptions.builder().withRandom(new SecureRandom()).withClock(Clock.systemUTC()).build();
        WasiPreview1 wasi = WasiPreview1.builder().withOptions(options).build();
        instance = Instance.builder(module)
                .withImportValues(ImportValues.builder().addFunction(wasi.toHostFunctions()).build())
                .withMachineFactory(MachineFactoryCompiler.compile(module))
                .withStart(false)
                .build();
        boolean reactor = false;
        for (int i = 0; i < module.exportSection().exportCount(); i++) {
            reactor |= module.exportSection().getExport(i).name().equals("_initialize");
        }
        if (reactor) instance.export("_initialize").apply();
        alloc = instance.export("ivar_alloc");
        free = instance.export("ivar_free");
        call = instance.export("ivar_call");
    }

    /** Send one request to the core. Throws IvarException on an error response. */
    public synchronized JsonNode call(String op, Object args, long handle) {
        ObjectNode req = JSON.createObjectNode();
        req.put("op", op);
        req.set("args", JSON.valueToTree(args == null ? JSON.createObjectNode() : args));
        if (handle != 0) req.put("handle", handle);
        byte[] data = req.toString().getBytes(StandardCharsets.UTF_8);
        int ptr = (int) alloc.apply(data.length)[0];
        instance.memory().write(ptr, data);
        long packed = call.apply(ptr, data.length)[0];
        free.apply(ptr, data.length);
        int outPtr = (int) (packed >>> 32);
        int outLen = (int) (packed & 0xFFFFFFFFL);
        byte[] out = instance.memory().readBytes(outPtr, outLen);
        free.apply(outPtr, Math.max(outLen, 1));
        try {
            JsonNode node = JSON.readTree(out);
            if (node.isObject() && node.size() == 1 && node.has("error")) throw new IvarException(node.get("error").asText());
            return node;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static final class IvarException extends RuntimeException {
        public IvarException(String message) {
            super(message);
        }
    }
}
