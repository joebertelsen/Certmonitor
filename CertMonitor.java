import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;

/**
 * TLS certificate expiry monitor / inventory tool.
 *
 * Run:  java CertMonitor.java hosts.txt [--warn 30] [--crit 14] [--timeout 5000] [--csv report.csv]
 * Exit code: 0 = all OK, 1 = at least one expired/expiring/misconfigured/unreachable target.
 *
 * Note: this tool inspects certificates on hosts you are authorized to test. Use it on
 * your own or your client's assets only.
 */
public class CertMonitor {

    record Target(String host, int port) {
        String label() { return host + ":" + port; }
    }

    record Result(Target target, String status, Long daysLeft, String notAfter, String subject,
                  String issuer, String keyInfo, String sigAlg, String tls, String issues) {}

    /** Records the chain and the validation failure (if any) instead of aborting the handshake. */
    static class CapturingTrustManager implements X509TrustManager {
        private final X509TrustManager delegate;
        volatile X509Certificate[] chain;
        volatile String validationError;

        CapturingTrustManager() throws Exception {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null); // JVM default trust store
            delegate = Arrays.stream(tmf.getTrustManagers())
                    .filter(t -> t instanceof X509TrustManager)
                    .map(t -> (X509TrustManager) t)
                    .findFirst().orElseThrow();
        }

        @Override public void checkClientTrusted(X509Certificate[] c, String a) {
            throw new UnsupportedOperationException();
        }

        @Override public void checkServerTrusted(X509Certificate[] c, String authType) {
            chain = c;
            try {
                delegate.checkServerTrusted(c, authType);
            } catch (CertificateException e) {
                validationError = e.getMessage();
            }
        }

        @Override public X509Certificate[] getAcceptedIssuers() { return delegate.getAcceptedIssuers(); }
    }

    // ---------- core check ----------

    static Result check(Target t, int timeoutMs, int warnDays, int critDays) {
        try {
            CapturingTrustManager tm = new CapturingTrustManager();
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{tm}, null);

            try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
                s.connect(new InetSocketAddress(t.host(), t.port()), timeoutMs);
                s.setSoTimeout(timeoutMs);
                SSLParameters p = s.getSSLParameters();
                try { p.setServerNames(List.of(new SNIHostName(t.host()))); }
                catch (IllegalArgumentException ignored) { /* IP literal: no SNI */ }
                s.setSSLParameters(p);
                s.startHandshake();

                X509Certificate leaf = tm.chain[0];
                Instant now = Instant.now();
                Instant notAfter = leaf.getNotAfter().toInstant();
                long days = ChronoUnit.DAYS.between(now, notAfter);

                String status = notAfter.isBefore(now) ? "EXPIRED"
                        : days <= critDays ? "CRITICAL"
                        : days <= warnDays ? "WARNING" : "OK";

                List<String> issues = new ArrayList<>();
                if (tm.validationError != null) issues.add("untrusted: " + tm.validationError);
                if (!matchesHost(leaf, t.host())) issues.add("hostname not in SAN");
                String tls = s.getSession().getProtocol();
                if (tls.equals("TLSv1") || tls.equals("TLSv1.1")) issues.add("legacy protocol " + tls);

                return new Result(t, status, days,
                        notAfter.atZone(ZoneOffset.UTC).toLocalDate().toString(),
                        leaf.getSubjectX500Principal().getName(),
                        leaf.getIssuerX500Principal().getName(),
                        keyInfo(leaf.getPublicKey()), leaf.getSigAlgName(), tls,
                        String.join("; ", issues));
            }
        } catch (Exception e) {
            return new Result(t, "ERROR", null, "-", "-", "-", "-", "-", "-",
                    e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    static String keyInfo(PublicKey k) {
        if (k instanceof RSAPublicKey r) return "RSA-" + r.getModulus().bitLength();
        if (k instanceof ECPublicKey e) return "EC-" + e.getParams().getOrder().bitLength();
        return k.getAlgorithm();
    }

    static boolean matchesHost(X509Certificate c, String host) throws CertificateParsingException {
        Collection<List<?>> sans = c.getSubjectAlternativeNames();
        if (sans == null) return false;
        for (List<?> san : sans) {
            int type = (Integer) san.get(0);          // 2 = DNS name, 7 = IP address
            if ((type == 2 || type == 7) && nameMatches((String) san.get(1), host)) return true;
        }
        return false;
    }

    static boolean nameMatches(String pattern, String host) {
        pattern = pattern.toLowerCase();
        host = host.toLowerCase();
        if (pattern.startsWith("*.")) {
            int dot = host.indexOf('.');
            return dot > 0 && host.substring(dot + 1).equals(pattern.substring(2));
        }
        return pattern.equals(host);
    }

    // ---------- input / output ----------

    static List<Target> loadTargets(Path file) throws IOException {
        List<Target> out = new ArrayList<>();
        for (String line : Files.readAllLines(file)) {
            int hash = line.indexOf('#');
            if (hash >= 0) line = line.substring(0, hash);
            line = line.strip();
            if (line.isEmpty()) continue;
            int idx = line.lastIndexOf(':');
            if (idx > 0) out.add(new Target(line.substring(0, idx), Integer.parseInt(line.substring(idx + 1))));
            else out.add(new Target(line, 443));
        }
        return out;
    }

    static void printTable(List<Result> results) {
        System.out.printf("%-34s %-9s %6s %-11s %-9s %s%n",
                "TARGET", "STATUS", "DAYS", "EXPIRES", "KEY", "ISSUES");
        for (Result r : results) {
            System.out.printf("%-34s %-9s %6s %-11s %-9s %s%n",
                    r.target().label(), r.status(),
                    r.daysLeft() == null ? "-" : r.daysLeft(),
                    r.notAfter(), r.keyInfo(), r.issues());
        }
    }

    static String csv(String v) {
        return "\"" + (v == null ? "" : v.replace("\"", "\"\"")) + "\"";
    }

    static void writeCsv(Path file, List<Result> results) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("host,port,status,days_left,not_after,subject,issuer,key,sig_alg,tls,issues");
        for (Result r : results) {
            lines.add(String.join(",",
                    csv(r.target().host()), String.valueOf(r.target().port()), csv(r.status()),
                    r.daysLeft() == null ? "" : r.daysLeft().toString(), csv(r.notAfter()),
                    csv(r.subject()), csv(r.issuer()), csv(r.keyInfo()), csv(r.sigAlg()),
                    csv(r.tls()), csv(r.issues())));
        }
        Files.write(file, lines);
    }

    // ---------- main ----------

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("Usage: java CertMonitor.java <hosts-file> [--warn 30] [--crit 14] [--timeout 5000] [--csv out.csv]");
            System.exit(2);
        }
        Path hostsFile = Path.of(args[0]);
        int warn = 30, crit = 14, timeout = 5000;
        Path csvOut = null;
        for (int i = 1; i < args.length - 1; i += 2) {
            switch (args[i]) {
                case "--warn" -> warn = Integer.parseInt(args[i + 1]);
                case "--crit" -> crit = Integer.parseInt(args[i + 1]);
                case "--timeout" -> timeout = Integer.parseInt(args[i + 1]);
                case "--csv" -> csvOut = Path.of(args[i + 1]);
                default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }

        List<Target> targets = loadTargets(hostsFile);
        Semaphore limit = new Semaphore(50);           // cap simultaneous connections
        final int w = warn, c = crit, to = timeout;
        List<Result> results = new ArrayList<>();

        try (ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Result>> futures = targets.stream().map(t -> ex.submit(() -> {
                limit.acquire();
                try { return check(t, to, w, c); } finally { limit.release(); }
            })).toList();
            for (Future<Result> f : futures) results.add(f.get());
        }

        // Most urgent first: errors, then fewest days remaining
        results.sort(Comparator.comparingLong(r -> r.daysLeft() == null ? Long.MIN_VALUE : r.daysLeft()));

        printTable(results);
        Map<String, Long> counts = new TreeMap<>();
        results.forEach(r -> counts.merge(r.status(), 1L, Long::sum));
        System.out.println("\nSummary: " + counts + " (" + results.size() + " targets)");

        if (csvOut != null) {
            writeCsv(csvOut, results);
            System.out.println("CSV written to " + csvOut);
        }

        boolean allClean = results.stream().allMatch(r -> r.status().equals("OK") && r.issues().isEmpty());
        System.exit(allClean ? 0 : 1);
    }
}