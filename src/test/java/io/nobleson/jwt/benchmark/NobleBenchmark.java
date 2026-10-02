/*
 * Nobleson JWT
 * https://github.com/Eselase-Noble/jwt
 *
 * Author:  Noble Eselase Vulley
 * Version: 0.1.0
 * Date:    2026-10-02
 */
package io.nobleson.jwt.benchmark;

import io.nobleson.jwt.Jwt;
import io.nobleson.jwt.Keys;
import io.nobleson.jwt.Nobleson;
import io.nobleson.jwt.algorithm.Algorithm;
import io.nobleson.jwt.algorithm.Algorithms;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.security.KeyPair;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Sign and verify throughput for each algorithm family. Run with:
 *
 * <pre>
 * mvn -q test-compile exec:java -Dexec.mainClass=org.openjdk.jmh.Main -Dexec.classpathScope=test
 * </pre>
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class NobleBenchmark {

    private Algorithm hs256;
    private Algorithm rs256Sign;
    private Algorithm rs256Verify;
    private Algorithm es256Sign;
    private Algorithm es256Verify;

    private String hsToken;
    private String rsToken;
    private String esToken;

    @Setup
    public void setup() {
        hs256 = Algorithms.hs256("a-very-long-and-secure-shared-secret-key");

        KeyPair rsa = Keys.rsaKeyPair();
        rs256Sign = Algorithms.rs256(rsa.getPrivate());
        rs256Verify = Algorithms.rs256(rsa.getPublic());

        KeyPair ec = Keys.ecKeyPair();
        es256Sign = Algorithms.es256(ec.getPrivate());
        es256Verify = Algorithms.es256(ec.getPublic());

        hsToken = sign(hs256);
        rsToken = sign(rs256Sign);
        esToken = sign(es256Sign);
    }

    private String sign(Algorithm algorithm) {
        return Nobleson.builder()
                .subject("user-123")
                .issuer("benchmark")
                .claim("role", "admin")
                .expiresIn(Duration.ofHours(1))
                .signWith(algorithm)
                .generate();
    }

    @Benchmark
    public String signHs256() {
        return sign(hs256);
    }

    @Benchmark
    public Jwt verifyHs256() {
        return Nobleson.parser().verifyWith(hs256).parse(hsToken);
    }

    @Benchmark
    public String signRs256() {
        return sign(rs256Sign);
    }

    @Benchmark
    public Jwt verifyRs256() {
        return Nobleson.parser().verifyWith(rs256Verify).parse(rsToken);
    }

    @Benchmark
    public String signEs256() {
        return sign(es256Sign);
    }

    @Benchmark
    public Jwt verifyEs256() {
        return Nobleson.parser().verifyWith(es256Verify).parse(esToken);
    }
}
