package com.learn.api_gateway.config;

import java.time.Duration;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.listener.ReactiveRedisMessageListenerContainer;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.RedisSerializer;

import com.learn.api_gateway.service.RedisLeaderLock;

import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.codec.RedisCodec;
import io.lettuce.core.codec.StringCodec;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
public class RedisConfig {
	
//	private RedisClient bucket4jClient;
//    private StatefulRedisConnection<String, byte[]> bucket4jConnection;
//    private final Map<String, Bucket> localBuckets = new ConcurrentHashMap<>();
//    private final Map<String, BucketConfiguration> bucketConfigs = new ConcurrentHashMap<>();
	@Value("${spring.data.redis.url}")
    private String redisUri;
	
	@Bean(destroyMethod = "shutdown")
    public RedisClient bucket4jRedisClient() {
        // create Lettuce RedisClient for Bucket4j proxy manager
        return RedisClient.create(redisUri);
    }

    @Bean(destroyMethod = "close")
    public StatefulRedisConnection<String, byte[]> bucket4jStatefulConnection(RedisClient bucket4jRedisClient) {
        // Use String keys and byte[] values as required by Bucket4j
        RedisCodec<String, byte[]> codec = RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE);
        return bucket4jRedisClient.connect(codec);
    }
    
	@Bean
    public LettuceBasedProxyManager<String> proxyManager(StatefulRedisConnection<String, byte[]> bucket4jStatefulConnection) {        
        return LettuceBasedProxyManager.<String>builderFor(bucket4jStatefulConnection)
                .withExpirationStrategy(
                        ExpirationAfterWriteStrategy.basedOnTimeForRefillingBucketUpToMax(Duration.ofSeconds(10))
                )
                .build();
    }

    // ----------------------------------------------------------------------------------------
    // Reactive Redis Templates
    // ----------------------------------------------------------------------------------------

    @Bean
    public ReactiveRedisTemplate<String, String> reactiveRedisTemplate(LettuceConnectionFactory factory) {
        RedisSerializationContext<String, String> context = RedisSerializationContext
                .<String, String>newSerializationContext(RedisSerializer.string())
                .key(RedisSerializer.string())
                .value(RedisSerializer.string())
                .hashKey(RedisSerializer.string())
                .hashValue(RedisSerializer.string())
                .build();
        return new ReactiveRedisTemplate<>(factory, context);
    }

    @Bean
    public ReactiveRedisTemplate<String, Map<String, Object>> principalCache(LettuceConnectionFactory factory) {
        RedisSerializer<String> keySerializer = RedisSerializer.string();
        RedisSerializer<Object> jsonSerializer = new GenericJackson2JsonRedisSerializer();

        @SuppressWarnings("unchecked")
        RedisSerializer<Map<String, Object>> mapSerializer =
                (RedisSerializer<Map<String, Object>>) (RedisSerializer<?>) jsonSerializer;

        RedisSerializationContext<String, Map<String, Object>> context =
                RedisSerializationContext.<String, Map<String, Object>>newSerializationContext(keySerializer)
                        .key(keySerializer)
                        .value(mapSerializer)
                        .hashKey(keySerializer)
                        .hashValue(mapSerializer)
                        .build();

        return new ReactiveRedisTemplate<>(factory, context);
    }

    // ----------------------------------------------------------------------------------------
    // Bucket4j Redis Client — explicit, isolated connection
    // ---------------------------------------------------------------------------------------    
    @Bean
    public ReactiveRedisTemplate<String, byte[]> reactiveByteRedisTemplate(LettuceConnectionFactory factory) {
        RedisSerializer<String> keySerializer = RedisSerializer.string();
        RedisSerializer<byte[]> valueSerializer = RedisSerializer.byteArray();

        RedisSerializationContext<String, byte[]> context =
                RedisSerializationContext.<String, byte[]>newSerializationContext(keySerializer)
                        .key(keySerializer)
                        .value(valueSerializer)
                        .hashKey(keySerializer)
                        .hashValue(valueSerializer)
                        .build();

        return new ReactiveRedisTemplate<>(factory, context);
    }

    /**
     * Bucket4j ProxyManager using the dedicated Lettuce connection.
     */
//    @Bean
//    public ProxyManager<String> bucket4jProxyManager() {
//        log.info("Using NoopProxyManager (in-memory rate-limiting) local Gateway node.");
//        
//        return new ProxyManager<>() {
//
//            @Override
//            public void removeProxy(String key) {
//                localBuckets.remove(key);
//                bucketConfigs.remove(key);
//                log.debug("Removed bucket for key={}", key);
//            }
//
//            @Override
//            public boolean isAsyncModeSupported() {
//                return false;
//            }
//
//            @Override
//            public Optional<BucketConfiguration> getProxyConfiguration(String key) {
//                return Optional.ofNullable(bucketConfigs.get(key));
//            }
//
//            @Override
//            public RemoteBucketBuilder<String> builder() {
//                return new RemoteBucketBuilder<>() {
//
//                    private RecoveryStrategy recoveryStrategy = RecoveryStrategy.RECONSTRUCT;
//                    private TokensInheritanceStrategy inheritanceStrategy = TokensInheritanceStrategy.AS_IS;
//
//                    @Override
//                    public RemoteBucketBuilder<String> withRecoveryStrategy(RecoveryStrategy strategy) {
//                        this.recoveryStrategy = strategy;
//                        return this;
//                    }
//
//                    @Override
//                    public RemoteBucketBuilder<String> withImplicitConfigurationReplacement(
//                            long desiredConfigurationVersion,
//                            TokensInheritanceStrategy strategy) {
//                        this.inheritanceStrategy = strategy;
//                        return this;
//                    }
//
//                    @Override
//                    public BucketProxy build(String key, BucketConfiguration configuration) {
//                        return createOrGetLocalBucket(key, configuration);
//                    }
//
//                    @Override
//                    public BucketProxy build(String key, Supplier<BucketConfiguration> supplier) {
//                        return createOrGetLocalBucket(key, supplier.get());
//                    }
//
//                    private BucketProxy createOrGetLocalBucket(String key, BucketConfiguration config) {
//                        return (BucketProxy) localBuckets.computeIfAbsent(key, k -> {
//                            log.info("Creating new local bucket for key={} [recovery={}, inherit={}]", 
//                                    key, recoveryStrategy, inheritanceStrategy);
//
//                            Bandwidth[] limits = config.getBandwidths();
//                            Bucket bucket = Bucket.builder()
//                                    .addLimit(limits[0])
//                                    .build();
//
//                            bucketConfigs.put(key, config);
//                            return bucket;
//                        });
//                    }
//
//                    @Override
//                    public RemoteBucketBuilder<String> withOptimization(Optimization optimization) {
//                        return this;
//                    }
//                };
//            }
//
//            @Override
//            public AsyncProxyManager<String> asAsync() {
//                throw new UnsupportedOperationException("Async mode not supported for in-memory NoopProxyManager");
//            }
//        };
//    }
    
//    @Bean
//    public BucketConfiguration defaultBucketConfiguration() {
//    	return BucketConfiguration.builder()
//                .addLimit(Bandwidth.builder()
//                        .capacity(100)
//                        .refillIntervally(100, Duration.ofMinutes(1))
//                        .build())
//                .build();
//    }

    // ----------------------------------------------------------------------------------------
    // Other Redis Infrastructure Beans
    // ----------------------------------------------------------------------------------------
    @Bean
    public ReactiveRedisMessageListenerContainer reactiveRedisMessageListenerContainer(
            LettuceConnectionFactory factory) {
        return new ReactiveRedisMessageListenerContainer(factory);
    }

    @Bean
    public RedisLeaderLock geoipRedisLeaderLock(
            ReactiveStringRedisTemplate redisTemplate,
            @Value("${geoip.leader.lock-key:geoip:leader}") String lockKey,
            @Value("${spring.application.name:${HOSTNAME:unknown}}") String nodeId,
            @Value("${geoip.leader.ttl-seconds:30}") long ttlSeconds,
            MeterRegistry meterRegistry,
            Environment env) {

        return new RedisLeaderLock(redisTemplate, lockKey, nodeId, ttlSeconds, meterRegistry, env);
    }

    
}
