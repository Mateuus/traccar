/*
 * Copyright 2026 RDM Rastreamento
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.api.resource;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.traccar.api.BaseResource;
import org.traccar.database.StatisticsManager;
import org.traccar.helper.Log;
import org.traccar.storage.StorageException;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Saúde do processo do servidor — CPU, memória, disco e descritores de arquivo.
 *
 * <p><b>Adição da RDM, não faz parte do Traccar de upstream.</b> Existe porque a
 * central precisa responder "o servidor está aguentando?" sem SSH: quem opera de
 * madrugada não abre terminal, abre o painel. O Traccar publica só
 * {@code /api/health} (um "OK" de texto), {@code /api/statistics} (agregado
 * diário) e o espaço em disco de carona no {@code /api/server} — nada de CPU nem
 * de RAM.
 *
 * <p>É um <b>arquivo novo</b> de propósito. O registro de recursos é por varredura
 * de pacote ({@code resourceConfig.packages(...)} em {@code WebServer}), então
 * nada precisa ser editado para ligá-lo — e um arquivo que só nasce não conflita
 * ao trazer o upstream de volta.
 *
 * <h2>🐞 Por que isto lê /proc em vez de usar a API da JVM</h2>
 *
 * <p>A primeira versão usava {@code com.sun.management.OperatingSystemMXBean},
 * que entrega CPU do processo, RAM da máquina e descritores prontos. Ela
 * funcionou na bancada e <b>quebrou no servidor</b> com
 * {@code NoClassDefFoundError: com/sun/management/OperatingSystemMXBean}.
 *
 * <p>O motivo: o Traccar é instalado com um <b>JRE enxuto</b>
 * ({@code /opt/traccar/jre}, 24 módulos) que traz {@code java.management} mas
 * <b>não</b> {@code jdk.management} — o módulo onde essa classe mora. Na bancada
 * havia um JDK completo, e por isso o teste passou verde enquanto o servidor
 * real não tinha como executar aquele código.
 *
 * <p>A leitura direta de {@code /proc} depende só de {@code java.base}, que
 * existe em qualquer runtime. Fora do Linux os campos vêm <b>nulos</b>, nunca
 * zero: zero leria como "servidor ocioso", e não saber é diferente de estar
 * livre.
 *
 * <h2>CPU precisa de duas amostras</h2>
 *
 * <p>{@code /proc} conta tempo acumulado, não percentual. A carga é a razão
 * entre o que o processo gastou e o que a máquina teve de capacidade
 * <b>entre duas leituras</b> — por isso a última amostra fica num campo estático,
 * e a primeira chamada depois de subir devolve nulo. O painel pergunta a cada 5
 * segundos, então a segunda resposta já vem completa.
 *
 * <p>Como as duas medidas saem do mesmo contador (jiffies), a razão é
 * adimensional: não é preciso saber quantos jiffies o sistema dá por segundo.
 */
@Path("metrics")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class MetricsResource extends BaseResource {

    /** Amostra de tempo de CPU, em jiffies, para a diferença da próxima leitura. */
    private record CpuSample(long process, long total, long idle) { }

    private static final Object CPU_LOCK = new Object();
    private static CpuSample lastCpuSample;

    @Inject
    private StatisticsManager statisticsManager;

    @GET
    public Map<String, Object> get() throws StorageException {
        permissionsService.checkAdmin(getUserId());

        OperatingSystemMXBean os = ManagementFactory.getOperatingSystemMXBean();
        RuntimeMXBean runtime = ManagementFactory.getRuntimeMXBean();
        MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
        ThreadMXBean threads = ManagementFactory.getThreadMXBean();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("uptime", runtime.getUptime());
        result.put("startTime", runtime.getStartTime());
        result.put("javaVersion", runtime.getSpecVersion());
        result.put("cpu", cpu(os));
        result.put("memory", memory(memory));
        result.put("threads", threads.getThreadCount());
        result.put("descriptors", descriptors());
        result.put("storage", Log.getStorageSpace());
        // Acumulado do período corrente. Quem chama tira a taxa da diferença
        // entre duas leituras — o servidor não guarda janela para isso.
        result.put("messagesStored", statisticsManager.messageStoredCount());

        return result;
    }

    /* ─── CPU ────────────────────────────────────────────────────────────── */

    private Map<String, Object> cpu(OperatingSystemMXBean os) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("cores", os.getAvailableProcessors());
        // -1 quando o sistema não publica a média de carga (Windows).
        double loadAverage = os.getSystemLoadAverage();
        result.put("loadAverage", loadAverage >= 0 ? loadAverage : null);

        Double process = null;
        Double system = null;
        CpuSample sample = readCpuSample();
        if (sample != null) {
            synchronized (CPU_LOCK) {
                CpuSample before = lastCpuSample;
                if (before != null) {
                    long totalDelta = sample.total() - before.total();
                    if (totalDelta > 0) {
                        long processDelta = sample.process() - before.process();
                        long idleDelta = sample.idle() - before.idle();
                        process = clamp(processDelta / (double) totalDelta);
                        system = clamp(1.0 - idleDelta / (double) totalDelta);
                    }
                }
                lastCpuSample = sample;
            }
        }
        result.put("process", process);
        result.put("system", system);
        return result;
    }

    /**
     * Tempo de CPU do processo e da máquina, dos dois arquivos que o kernel
     * publica. Devolve nulo fora do Linux — lá {@code /proc} não existe.
     */
    private CpuSample readCpuSample() {
        try {
            long[] machine = readMachineCpu();
            if (machine == null) {
                return null;
            }
            long process = readProcessCpu();
            if (process < 0) {
                return null;
            }
            return new CpuSample(process, machine[0], machine[1]);
        } catch (IOException | RuntimeException error) {
            return null;
        }
    }

    /** `[total, ocioso]` da primeira linha de /proc/stat, em jiffies. */
    private long[] readMachineCpu() throws IOException {
        var path = Paths.get("/proc/stat");
        if (!Files.exists(path)) {
            return null;
        }
        for (String line : Files.readAllLines(path)) {
            if (line.startsWith("cpu ")) {
                String[] parts = line.trim().split("\\s+");
                long total = 0;
                // parts[0] é o rótulo "cpu"; do 1 em diante são os contadores.
                for (int i = 1; i < parts.length; i++) {
                    total += Long.parseLong(parts[i]);
                }
                // Campos 4 e 5 são idle e iowait: a máquina não estava fazendo
                // trabalho útil em nenhum dos dois.
                long idle = Long.parseLong(parts[4]) + Long.parseLong(parts[5]);
                return new long[] {total, idle};
            }
        }
        return null;
    }

    /** `utime + stime` de /proc/self/stat, em jiffies. `-1` se não der para ler. */
    private long readProcessCpu() throws IOException {
        var path = Paths.get("/proc/self/stat");
        if (!Files.exists(path)) {
            return -1;
        }
        String content = Files.readString(path);
        // ⚠️ O nome do processo vem entre parênteses e PODE conter espaços e
        // parênteses. Cortar pelo ÚLTIMO ')' é o único jeito seguro de alinhar
        // os campos — dividir por espaço desde o começo desalinha tudo.
        int cut = content.lastIndexOf(')');
        if (cut < 0) {
            return -1;
        }
        String[] parts = content.substring(cut + 1).trim().split("\\s+");
        // Depois do ')' o primeiro campo é o 3 (estado); utime é o 14 e stime o
        // 15, logo índices 11 e 12.
        if (parts.length < 13) {
            return -1;
        }
        return Long.parseLong(parts[11]) + Long.parseLong(parts[12]);
    }

    private Double clamp(double value) {
        return Math.min(1.0, Math.max(0.0, value));
    }

    /* ─── memória ────────────────────────────────────────────────────────── */

    private Map<String, Object> memory(MemoryMXBean memory) {
        Map<String, Object> result = new LinkedHashMap<>();
        // Heap é o que a JVM administra; a RAM do sistema é o que sobra para
        // todo o resto. As duas contam uma história diferente quando aperta.
        result.put("heapUsed", memory.getHeapMemoryUsage().getUsed());
        result.put("heapMax", memory.getHeapMemoryUsage().getMax());
        result.put("nonHeapUsed", memory.getNonHeapMemoryUsage().getUsed());

        Long total = null;
        Long available = null;
        try {
            var path = Paths.get("/proc/meminfo");
            if (Files.exists(path)) {
                for (String line : Files.readAllLines(path)) {
                    if (line.startsWith("MemTotal:")) {
                        total = parseKilobytes(line);
                    } else if (line.startsWith("MemAvailable:")) {
                        // MemAvailable, e não MemFree: o kernel conta aqui o que
                        // dá para recuperar de cache. MemFree num servidor
                        // saudável é sempre baixo e assustaria à toa.
                        available = parseKilobytes(line);
                    }
                }
            }
        } catch (IOException | RuntimeException error) {
            total = null;
            available = null;
        }
        result.put("systemTotal", total);
        result.put("systemFree", available);
        return result;
    }

    /** "MemTotal:  32752124 kB" → bytes. */
    private Long parseKilobytes(String line) {
        String[] parts = line.trim().split("\\s+");
        return parts.length >= 2 ? Long.parseLong(parts[1]) * 1024 : null;
    }

    /* ─── descritores ────────────────────────────────────────────────────── */

    /**
     * Descritor de arquivo é métrica de rastreamento, não de sistema: cada
     * rastreador conectado é um socket, e socket é descritor. Numa frota grande
     * é este teto que estoura primeiro, muito antes da CPU — e o sintoma é
     * cruel, porque o servidor continua de pé, respondendo ao painel, e só para
     * de aceitar conexão nova.
     */
    private Map<String, Object> descriptors() {
        try {
            var directory = Paths.get("/proc/self/fd");
            if (!Files.exists(directory)) {
                return null;
            }
            long open;
            try (var entries = Files.list(directory)) {
                open = entries.count();
            }
            Long max = null;
            var limits = Paths.get("/proc/self/limits");
            if (Files.exists(limits)) {
                List<String> lines = Files.readAllLines(limits);
                for (String line : lines) {
                    if (line.startsWith("Max open files")) {
                        String[] parts = line.trim().split("\\s{2,}");
                        if (parts.length >= 2) {
                            max = "unlimited".equals(parts[1]) ? null : Long.parseLong(parts[1]);
                        }
                    }
                }
            }
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("open", open);
            result.put("max", max);
            return result;
        } catch (IOException | RuntimeException error) {
            return null;
        }
    }

}
