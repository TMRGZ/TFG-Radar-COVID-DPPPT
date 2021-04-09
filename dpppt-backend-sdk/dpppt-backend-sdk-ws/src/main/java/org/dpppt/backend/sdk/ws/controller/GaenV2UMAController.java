package org.dpppt.backend.sdk.ws.controller;

import ch.ubique.openapi.docannotations.Documentation;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.dpppt.backend.sdk.data.gaen.FakeKeyService;
import org.dpppt.backend.sdk.data.gaen.GAENDataService;
import org.dpppt.backend.sdk.model.gaen.GaenKey;
import org.dpppt.backend.sdk.model.gaen.GaenV2UploadKeysRequest;
import org.dpppt.backend.sdk.utils.DurationExpiredException;
import org.dpppt.backend.sdk.utils.UTCInstant;
import org.dpppt.backend.sdk.ws.insertmanager.InsertException;
import org.dpppt.backend.sdk.ws.insertmanager.InsertManager;
import org.dpppt.backend.sdk.ws.insertmanager.insertionfilters.AssertKeyFormat.KeyFormatException;
import org.dpppt.backend.sdk.ws.radarcovid.annotation.Loggable;
import org.dpppt.backend.sdk.ws.security.ValidateRequest;
import org.dpppt.backend.sdk.ws.security.ValidateRequest.ClaimIsBeforeOnsetException;
import org.dpppt.backend.sdk.ws.security.ValidateRequest.InvalidDateException;
import org.dpppt.backend.sdk.ws.security.ValidateRequest.WrongScopeException;
import org.dpppt.backend.sdk.ws.security.signature.ProtoSignature;
import org.dpppt.backend.sdk.ws.security.signature.ProtoSignature.ProtoSignatureWrapper;
import org.dpppt.backend.sdk.ws.util.ValidationUtils;
import org.dpppt.backend.sdk.ws.util.ValidationUtils.BadBatchReleaseTimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;

/** This is a new controller to simplify the sending and receiving of keys using ENv1.5/ENv2 and a CuckooFilter. */
@Controller
@RequestMapping("/v2UMA/gaen")
@Documentation(description = "The GAEN V2-UMA endpoint for clients supporting the final project development")
public class GaenV2UMAController {

  private static final Logger logger = LoggerFactory.getLogger(GaenV2UMAController.class);

  private final InsertManager insertManager;

  private final ValidateRequest validateRequest;

  private final ValidationUtils validationUtils;
  private final FakeKeyService fakeKeyService;
  private final ProtoSignature gaenSigner;
  private final GAENDataService dataService;
  private final Duration releaseBucketDuration;
  private final Duration requestTime;
  private final Duration exposedListCacheControl;
  private final Duration retentionPeriod;

  private static final String HEADER_X_KEY_BUNDLE_TAG = "x-key-bundle-tag";

  private static final DateTimeFormatter RFC1123_DATE_TIME_FORMATTER =
          DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'")
                  .withZone(ZoneOffset.UTC).withLocale(Locale.ENGLISH);

  public GaenV2UMAController(
      InsertManager insertManager,
      ValidateRequest validateRequest,
      ValidationUtils validationUtils,
      FakeKeyService fakeKeyService,
      ProtoSignature gaenSigner,
      GAENDataService dataService,
      Duration releaseBucketDuration,
      Duration requestTime,
      Duration exposedListCacheControl,
      Duration retentionPeriod) {
    this.insertManager = insertManager;
    this.validateRequest = validateRequest;
    this.validationUtils = validationUtils;
    this.fakeKeyService = fakeKeyService;
    this.gaenSigner = gaenSigner;
    this.dataService = dataService;
    this.releaseBucketDuration = releaseBucketDuration;
    this.requestTime = requestTime;
    this.exposedListCacheControl = exposedListCacheControl;
    this.retentionPeriod = retentionPeriod;
  }

  @GetMapping(value = "")
  @Documentation(
      description = "Hello return",
      responses = {"200=>server live"})
  public @ResponseBody ResponseEntity<String> hello() {
    return ResponseEntity.ok().header("X-HELLO", "dp3t").body("Hello from DP3T WS GAEN V2-UMA");
  }

  @PostMapping(value = "/exposed")
  @Documentation(
      description = "Endpoint used to upload exposure keys to the backend",
      responses = {
        "200=>The exposed keys have been stored in the database",
        "400=> "
            + "- Invalid base64 encoding in GaenRequest"
            + "- negative rolling period"
            + "- fake claim with non-fake keys",
        "403=>Authentication failed"
      })
  @Loggable
  public @ResponseBody Callable<ResponseEntity<String>> addExposed(
      @Documentation(description = "JSON Object containing all keys.") @Valid @RequestBody
          GaenV2UploadKeysRequest gaenV2Request,
      @RequestHeader(value = "User-Agent")
          @Documentation(
              description =
                  "App Identifier (PackageName/BundleIdentifier) + App-Version +"
                      + " OS (Android/iOS) + OS-Version",
              example = "ch.ubique.android.dp3t;1.0;iOS;13.3")
          String userAgent,
      @AuthenticationPrincipal
          @Documentation(description = "JWT token that can be verified by the backend server")
          Object principal)
      throws WrongScopeException, InsertException {
    var now = UTCInstant.now();

    this.validateRequest.isValid(principal);

    // Filter out non valid keys and insert them into the database (c.f.
    // InsertManager and
    // configured Filters in the WSBaseConfig)
    insertManager.insertIntoDatabase(gaenV2Request.getGaenKeys(), userAgent, principal, now);
    var responseBuilder = ResponseEntity.ok();
    Callable<ResponseEntity<String>> cb =
        () -> {
          try {
            now.normalizeDuration(requestTime);
          } catch (DurationExpiredException e) {
            logger.debug("Total time spent in endpoint is longer than requestTime");
          }
          return responseBuilder.body("OK");
        };
    return cb;
  }

  // GET for CuckooFilter Download containing keys
  @GetMapping(value = "/exposed", produces = "application/zip")
  @Documentation(
      description = "Requests keys published _after_ lastKeyBundleTag.",
      responses = {
        "200 => zipped export.bin and export.sig of all keys in that interval",
        "404 => Invalid _lastKeyBundleTag_"
      })
  @Loggable
  public @ResponseBody ResponseEntity<byte[]> getExposedKeys(
      @Documentation(
              description =
                  "Only retrieve keys published after the specified key-bundle"
                      + " tag. Optional, if no tag set, all keys for the"
                      + " retention period are returned",
              example = "1593043200000")
          @RequestParam(required = false)
          Long lastKeyBundleTag,
      @Documentation(
              description =
	               "Visited countries list for exposed key retrieval. Optional, if not setted,"
	                  + " all visited countries are returned",
	          example = "IT, DE, PT")
          @RequestParam(required = false)
          List<String> visitedCountries,
      @Documentation(
              description =
                      "Origin countries list for exposed key retrieval. Optional, if not setted,"
                      + " all origin countries are returned",
              example = "IT, DE, PT")
      @RequestParam(required = false)
              List<String> originCountries)
      throws BadBatchReleaseTimeException, InvalidKeyException, SignatureException,
          NoSuchAlgorithmException, IOException {
    var now = UTCInstant.now();
    
    Long minimumLastKeyBundleTag =
            now.minus(retentionPeriod).roundToNextBucket(releaseBucketDuration).getTimestamp();
    if (lastKeyBundleTag == null || lastKeyBundleTag < minimumLastKeyBundleTag) {
      // if no lastKeyBundleTag given, go back to the start of the retention period and
      // select next bucket.
      lastKeyBundleTag =
    		  minimumLastKeyBundleTag;
    }
    var keysSince = UTCInstant.ofEpochMillis(lastKeyBundleTag);

    if (!validationUtils.isValidBatchReleaseTime(keysSince, now)) {
      return ResponseEntity.notFound().build();
    }
    UTCInstant keyBundleTag = now.roundToBucketStart(releaseBucketDuration);
    UTCInstant expiration = now.roundToNextBucket(releaseBucketDuration);

    List<GaenKey> exposedKeys = dataService.getSortedExposedSince(keysSince, now, visitedCountries, originCountries);

    if (exposedKeys.isEmpty()) {
      return ResponseEntity.noContent()
          //.cacheControl(CacheControl.maxAge(exposedListCacheControl))
          .header(HEADER_X_KEY_BUNDLE_TAG, Long.toString(keyBundleTag.getTimestamp()))
          .header("Expires", RFC1123_DATE_TIME_FORMATTER.format(expiration.getOffsetDateTime()))
          .build();
    }
    ProtoSignatureWrapper payload = gaenSigner.getPayloadV2UMA(exposedKeys);

    return ResponseEntity.ok()
        //.cacheControl(CacheControl.maxAge(exposedListCacheControl))
        .header(HEADER_X_KEY_BUNDLE_TAG, Long.toString(keyBundleTag.getTimestamp()))
        .header("Expires", RFC1123_DATE_TIME_FORMATTER.format(expiration.getOffsetDateTime()))
        .body(payload.getZip());
  }

  @ExceptionHandler({
    IllegalArgumentException.class,
    InvalidDateException.class,
    JsonProcessingException.class,
    MethodArgumentNotValidException.class,
    BadBatchReleaseTimeException.class,
    DateTimeParseException.class,
    ClaimIsBeforeOnsetException.class,
    KeyFormatException.class
  })
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ResponseEntity<Object> invalidArguments() {
    return ResponseEntity.badRequest().build();
  }

  @ExceptionHandler({WrongScopeException.class})
  @ResponseStatus(HttpStatus.FORBIDDEN)
  public ResponseEntity<Object> forbidden() {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
  }
}
