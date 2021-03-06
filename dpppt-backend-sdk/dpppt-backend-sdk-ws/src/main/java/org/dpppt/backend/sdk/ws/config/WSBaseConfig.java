/*
 * Copyright (c) 2020 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.dpppt.backend.sdk.ws.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.hubspot.jackson.datatype.protobuf.ProtobufModule;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.dpppt.backend.sdk.data.JDBCRedeemDataServiceImpl;
import org.dpppt.backend.sdk.data.RedeemDataService;
import org.dpppt.backend.sdk.data.gaen.FakeKeyService;
import org.dpppt.backend.sdk.data.gaen.GAENDataService;
import org.dpppt.backend.sdk.data.radarcovid.gaen.SpanishJDBCGAENDataServiceImpl;
import org.dpppt.backend.sdk.ws.controller.GaenController;
import org.dpppt.backend.sdk.ws.controller.GaenV2Controller;
import org.dpppt.backend.sdk.ws.controller.GaenV2UMAController;
import org.dpppt.backend.sdk.ws.filter.ResponseWrapperFilter;
import org.dpppt.backend.sdk.ws.insertmanager.InsertManager;
import org.dpppt.backend.sdk.ws.insertmanager.insertionfilters.*;
import org.dpppt.backend.sdk.ws.insertmanager.insertionmodifier.IOSLegacyProblemRPLT144Modifier;
import org.dpppt.backend.sdk.ws.insertmanager.insertionmodifier.OldAndroid0RPModifier;
import org.dpppt.backend.sdk.ws.interceptor.HeaderInjector;
import org.dpppt.backend.sdk.ws.radarcovid.client.ValidationClientService;
import org.dpppt.backend.sdk.ws.radarcovid.client.impl.ValidationClientServiceImpl;
import org.dpppt.backend.sdk.ws.radarcovid.client.service.ValidationRestClientService;
import org.dpppt.backend.sdk.ws.radarcovid.client.service.impl.ValidationCircuitBreakerRestClientServiceImpl;
import org.dpppt.backend.sdk.ws.radarcovid.client.service.impl.ValidationRetryableRestClientServiceImpl;
import org.dpppt.backend.sdk.ws.radarcovid.insertmanager.insertionmodifier.SpanishEFGSModifier;
import org.dpppt.backend.sdk.ws.security.KeyVault;
import org.dpppt.backend.sdk.ws.security.NoValidateRequest;
import org.dpppt.backend.sdk.ws.security.ValidateRequest;
import org.dpppt.backend.sdk.ws.security.signature.ProtoSignature;
import org.dpppt.backend.sdk.ws.util.ValidationUtils;
import org.flywaydb.core.Flyway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.converter.protobuf.ProtobufHttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider.Configuration.builder;

@Configuration
@EnableScheduling
@EnableSchedulerLock(defaultLockAtMostFor = "PT30S")
public abstract class WSBaseConfig implements WebMvcConfigurer {

  protected final Logger logger = LoggerFactory.getLogger(getClass());

  public abstract DataSource dataSource();

  public abstract Flyway flyway();

  public abstract String getDbType();

  @Value(
      "#{${ws.security.headers: {'X-Content-Type-Options':'nosniff',"
          + " 'X-Frame-Options':'DENY','X-Xss-Protection':'1; mode=block'}}}")
  Map<String, String> additionalHeaders;

  @Value("${ws.exposedlist.cachecontrol: 300000}")
  int exposedListCacheControl;

  @Value("${ws.headers.protected:}")
  List<String> protectedHeaders;

  @Value("${ws.headers.debug: false}")
  boolean setDebugHeaders;

  @Value("${ws.gaen.randomkeysenabled: false}")
  boolean randomkeysenabled;

  @Value("${ws.gaen.randomkeyamount: 10}")
  int randomkeyamount;

  @Value("${ws.retentiondays: 14}")
  int retentionDays;

  @Value("${ws.exposedlist.releaseBucketDuration: 7200000}")
  long releaseBucketDuration;

  @Value("${ws.exposedlist.requestTime: 1500}")
  long requestTime;

  @Value("${ws.app.source}")
  String appSource;

  @Value("${ws.app.gaen.region:ch}")
  String gaenRegion;

  @Value("${ws.app.gaen.key_size: 16}")
  int gaenKeySizeBytes;

  @Value("${ws.app.key_size: 32}")
  int keySizeBytes;

  @Value("${ws.app.ios.bundleId:org.dppt.ios.demo}")
  String bundleId;

  @Value("${ws.app.android.packageName:org.dpppt.android.demo}")
  String packageName;

  @Value("${ws.app.gaen.keyVersion:v1}")
  String keyVersion;

  @Value("${ws.app.gaen.keyIdentifier:228}")
  String keyIdentifier;

  @Value("${ws.app.gaen.algorithm:1.2.840.10045.4.3.2}")
  String gaenAlgorithm;

  @Value("${ws.app.gaen.timeskew:PT2h}")
  Duration timeSkew;

  @Value("${datasource.schema:}")
  String dataSourceSchema;

  @Value("${ws.app.efgs.country-origin:ES}")
  String efgsCountryOrigin;

  @Value("${ws.app.efgs.report-type:1}")
  int efgsReportType;

  @Autowired(required = false)
  ValidateRequest requestValidator;

  @Autowired(required = false)
  ValidateRequest gaenRequestValidator;

  @Autowired @Lazy KeyVault keyVault;

  final SignatureAlgorithm algorithm = SignatureAlgorithm.ES256;

  public String getBundleId() {
    return this.bundleId;
  }

  public String getPackageName() {
    return this.packageName;
  }

  public String getKeyVersion() {
    return this.keyVersion;
  }

  public String getKeyIdentifier() {
    return this.keyIdentifier;
  }

  @Bean
  public FakeKeyService fakeKeyService() {
    try {
      DataSource fakeDataSource =
          new EmbeddedDatabaseBuilder()
              .generateUniqueName(true)
              .setType(EmbeddedDatabaseType.HSQL)
              .build();
      Flyway flyWay =
          Flyway.configure()
              .dataSource(fakeDataSource)
              .locations("classpath:/db/migration/hsqldb")
              .load();
      flyWay.migrate();
      GAENDataService fakeGaenService =
          new SpanishJDBCGAENDataServiceImpl(
              "hsql", fakeDataSource, Duration.ofMillis(releaseBucketDuration), timeSkew);
      return new FakeKeyService(
          fakeGaenService,
          Integer.valueOf(randomkeyamount),
          Integer.valueOf(gaenKeySizeBytes),
          Duration.ofDays(retentionDays),
          randomkeysenabled,
          efgsCountryOrigin,
          efgsReportType);
    } catch (Exception ex) {
      throw new RuntimeException("FakeKeyService could not be instantiated", ex);
    }
  }

  @Bean
  public ProtoSignature gaenSigner() {
    try {
      return new ProtoSignature(
          gaenAlgorithm,
          keyVault.get("gaen"),
          getBundleId(),
          getPackageName(),
          getKeyVersion(),
          getKeyIdentifier(),
          gaenRegion,
          Duration.ofMillis(releaseBucketDuration));
    } catch (Exception ex) {
      throw new RuntimeException("Cannot initialize signer for protobuf");
    }
  }

  @Bean
  public InsertManager insertManagerExposed() {
    var manager = new InsertManager(gaenDataService(), gaenValidationUtils());
    manager.addFilter(new AssertKeyFormat(gaenValidationUtils()));
    manager.addFilter(new EnforceMatchingJWTClaimsForExposed(gaenRequestValidator));
    //manager.addFilter(new RemoveKeysFromFuture());
    manager.addFilter(new EnforceRetentionPeriod(gaenValidationUtils()));
    manager.addFilter(new RemoveFakeKeys());
    manager.addFilter(new EnforceValidRollingPeriod());
    manager.addModifier(new SpanishEFGSModifier(efgsCountryOrigin, efgsReportType));
    return manager;
  }

  @Bean
  public InsertManager insertManagerExposedNextDay() {
    var manager = new InsertManager(gaenDataService(), gaenValidationUtils());
    manager.addFilter(new AssertKeyFormat(gaenValidationUtils()));
    manager.addFilter(new EnforceMatchingJWTClaimsForExposedNextDay(gaenValidationUtils()));
    manager.addFilter(new RemoveKeysFromFuture());
    manager.addFilter(new EnforceRetentionPeriod(gaenValidationUtils()));
    manager.addFilter(new RemoveFakeKeys());
    manager.addFilter(new EnforceValidRollingPeriod());
    manager.addModifier(new SpanishEFGSModifier(efgsCountryOrigin, efgsReportType));
    return manager;
  }

  /**
   * Even though there are probably no android devices left that send TEKs with rollingPeriod of 0,
   * this modifier will not hurt. Every TEK with rollingPeriod of 0 will be reported.
   */
  @ConditionalOnProperty(
      value = "ws.app.gaen.insertmanager.android0rpmodifier",
      havingValue = "true",
      matchIfMissing = false)
  @Bean
  public OldAndroid0RPModifier oldAndroid0RPModifier(InsertManager manager) {
    var androidModifier = new OldAndroid0RPModifier();
    manager.addModifier(androidModifier);
    return androidModifier;
  }

  /**
   * This modifier will most probably not be enabled, as there should be very little iOS devices
   * left that cannot handle a non-144 rollingPeriod key. Also, up to 8th of September 2020, Android
   * did not release same day keys.
   */
  @ConditionalOnProperty(
      value = "ws.app.gaen.insertmanager.iosrplt144modifier",
      havingValue = "true",
      matchIfMissing = false)
  @Bean
  public IOSLegacyProblemRPLT144Modifier iosLegacyProblemRPLT144(InsertManager manager) {
    var iosModifier = new IOSLegacyProblemRPLT144Modifier();
    manager.addModifier(iosModifier);
    return iosModifier;
  }

  @Bean
  public ValidationUtils gaenValidationUtils() {
    return new ValidationUtils(
        gaenKeySizeBytes, Duration.ofDays(retentionDays), releaseBucketDuration);
  }

  @Bean
  RestTemplate restTemplate(RestTemplateBuilder builder) {
    return builder.build();
  }

  @Bean
  ValidationRestClientService validationRetryableRestClientService(RestTemplate restTemplate) {
    return new ValidationRetryableRestClientServiceImpl(restTemplate);
  }

  @Bean
  ValidationRestClientService validationCircuitBreakerRestClientService(@Qualifier("validationRetryableRestClientService") ValidationRestClientService validationRestClientService) {
    return new ValidationCircuitBreakerRestClientServiceImpl(validationRestClientService);
  }

  @Bean
  ValidationClientService validationClientService(@Qualifier("validationCircuitBreakerRestClientService") ValidationRestClientService validationRestClientService) {
    return new ValidationClientServiceImpl(validationRestClientService);
  }

  @Bean
  public GaenController gaenController() {
    ValidateRequest theValidator = gaenRequestValidator;
    if (theValidator == null) {
      theValidator = backupValidator();
    }
    return new GaenController(
        insertManagerExposed(),
        insertManagerExposedNextDay(),
        gaenDataService(),
        fakeKeyService(),
        theValidator,
        gaenSigner(),
        gaenValidationUtils(),
        Duration.ofMillis(releaseBucketDuration),
        Duration.ofMillis(requestTime),
        Duration.ofMillis(exposedListCacheControl),
        keyVault.get("nextDayJWT").getPrivate());
  }

  @Bean
  public GaenV2Controller gaenV2Controller() {
    ValidateRequest theValidator = gaenRequestValidator;
    if (theValidator == null) {
      theValidator = backupValidator();
    }
    return new GaenV2Controller(
        insertManagerExposed(),
        theValidator,
        gaenValidationUtils(),
        fakeKeyService(),
        gaenSigner(),
        gaenDataService(),
        Duration.ofMillis(releaseBucketDuration),
        Duration.ofMillis(requestTime),
        Duration.ofMillis(exposedListCacheControl),
        Duration.ofDays(retentionDays));
  }

  @Bean
  public GaenV2UMAController gaenV2UMAController() {
    ValidateRequest theValidator = gaenRequestValidator;
    if (theValidator == null) {
      theValidator = backupValidator();
    }
    return new GaenV2UMAController(
            insertManagerExposed(),
            theValidator,
            gaenValidationUtils(),
            fakeKeyService(),
            gaenSigner(),
            gaenDataService(),
            Duration.ofMillis(releaseBucketDuration),
            Duration.ofMillis(requestTime),
            Duration.ofMillis(exposedListCacheControl),
            Duration.ofDays(retentionDays));
  }

  @Bean
  public GAENDataService gaenDataService() {
    return new SpanishJDBCGAENDataServiceImpl(
        getDbType(), dataSource(), Duration.ofMillis(releaseBucketDuration), timeSkew);
  }

  @Bean
  public RedeemDataService redeemDataService() {
    return new JDBCRedeemDataServiceImpl(dataSource());
  }

  @Bean
  ValidateRequest backupValidator() {
    return new NoValidateRequest();
  }

  @Bean
  public MappingJackson2HttpMessageConverter converter() {
    ObjectMapper mapper =
        new ObjectMapper()
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
            .setSerializationInclusion(JsonInclude.Include.NON_ABSENT)
            .registerModules(new ProtobufModule(), new Jdk8Module());
    return new MappingJackson2HttpMessageConverter(mapper);
  }

  @Override
  public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
    converters.add(new ProtobufHttpMessageConverter());
    WebMvcConfigurer.super.extendMessageConverters(converters);
  }

  @Bean
  public ResponseWrapperFilter hashFilter() {
    return new ResponseWrapperFilter(
        keyVault.get("hashFilter"), retentionDays, protectedHeaders, setDebugHeaders);
  }

  @Bean
  public HeaderInjector securityHeaderInjector() {
    return new HeaderInjector(additionalHeaders);
  }

  public KeyPair getKeyPair(SignatureAlgorithm algorithm) {
    logger.warn(
        "USING FALLBACK KEYPAIR. WONT'T PERSIST APP RESTART AND PROBABLY DOES NOT HAVE ENOUGH"
            + " ENTROPY.");

    return Keys.keyPairFor(algorithm);
  }

  @Override
  public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
    configurer.setTaskExecutor(mvcTaskExecutor());
    configurer.setDefaultTimeout(5_000);
  }

  @Bean
  public ThreadPoolTaskExecutor mvcTaskExecutor() {
    ThreadPoolTaskExecutor taskExecutor = new ThreadPoolTaskExecutor();
    taskExecutor.setThreadNamePrefix("mvc-task-");
    taskExecutor.setMaxPoolSize(1000);
    return taskExecutor;
  }

  /**
   * Creates a LockProvider for ShedLock.
   *
   * @param dataSource JPA datasource
   * @return LockProvider
   */
  @Bean
  public LockProvider lockProvider(DataSource dataSource) {
    String tableName = StringUtils.isEmpty(dataSourceSchema) ? "shedlock" : dataSourceSchema + ".shedlock";
    return new JdbcTemplateLockProvider(builder()
                                                .withTableName(tableName)
                                                .withJdbcTemplate(new JdbcTemplate(dataSource))
                                                .usingDbTime()
                                                .build()
    );
  }

  @Scheduled(fixedRate = 60 * 60 * 1000L, initialDelay = 60 * 1000L)
  @SchedulerLock(name = "cleanData", lockAtLeastFor = "PT0S", lockAtMostFor = "1800000")
  public void scheduleCleanData() {
    logger.info("Start DB cleanup");
    gaenDataService().cleanDB(Duration.ofDays(retentionDays));
    redeemDataService().cleanDB(Duration.ofDays(2));
    logger.info("DB cleanup up");
  }

  @Scheduled(cron = "0 0 2 * * *")
  @SchedulerLock(name = "updateFakeKeys", lockAtLeastFor = "PT0S", lockAtMostFor = "1800000")
  public void scheduleUpdateFakeKeys() {
    logger.info("Start Update Fake Keys");
    fakeKeyService().updateFakeKeys();
    logger.info("End Update Fake Keys");
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(securityHeaderInjector());
  }

}
