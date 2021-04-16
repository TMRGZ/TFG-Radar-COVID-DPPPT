/*
 * Copyright (c) 2020 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package org.dpppt.backend.sdk.ws.controller;

import org.dpppt.backend.sdk.data.gaen.GAENDataService;
import org.dpppt.backend.sdk.model.gaen.GaenKey;
import org.dpppt.backend.sdk.model.gaen.GaenRequest;
import org.dpppt.backend.sdk.model.gaen.GaenV2UploadKeysRequest;
import org.dpppt.backend.sdk.utils.UTCInstant;
import org.dpppt.backend.sdk.ws.security.KeyVault;
import org.dpppt.backend.sdk.ws.security.signature.ProtoSignature;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ActiveProfiles({"actuator-security"})
@SpringBootTest(
    properties = {
      "ws.app.jwt.publickey=classpath://generated_pub.pem",
      "logging.level.org.springframework.security=DEBUG",
      "ws.exposedlist.releaseBucketDuration=7200000",
      "ws.gaen.randomkeysenabled=true",
      "ws.monitor.prometheus.user=prometheus",
      "ws.monitor.prometheus.password=prometheus",
      "management.endpoints.enabled-by-default=true",
      "management.endpoints.web.exposure.include=*"
    })
@Transactional
public class GaenV2UMAControllerTest extends BaseControllerTest {
  @Autowired ProtoSignature signer;
  @Autowired KeyVault keyVault;
  @Autowired GAENDataService gaenDataService;

  Duration releaseBucketDuration = Duration.ofMillis(7200000L);

  private static final Logger logger = LoggerFactory.getLogger(GaenV2UMAControllerTest.class);


  @Test
  @Transactional
  public void zipContainsFilter() throws Exception {
    var midnight = UTCInstant.today();

    // Insert two times 5 keys per day for the last 14 days. the second batch has a
    // different 'received at' timestamp. (+12 hours compared to the first)

    insertNKeysPerDay(midnight, 14, 5, midnight.minusDays(1), false);
    insertNKeysPerDay(midnight, 14, 5, midnight.minusHours(12), false);

    // request the keys with key date 8 days ago. no publish until.
    MockHttpServletResponse response =
            mockMvc
                    .perform(
                            get("/v2UMA/gaen/exposed"+ midnight.minusDays(8).getTimestamp())
                                    .header("User-Agent", "MockMVC"))
                    .andExpect(status().is2xxSuccessful())
                    .andReturn()
                    .getResponse();

    /*Long publishedUntil = Long.parseLong(response.getHeader("X-PUBLISHED-UNTIL"));
    assertTrue(
            publishedUntil <= UTCInstant.now().getTimestamp(), "Published until must be in the past");*/

    // must contain 20 keys: 5 from the first insert, 5 from the second insert and
    // 10 random keys
    verifyZipResponse(response, 20);

    // request again the keys with date date 8 days ago. with publish until, so that
    // we only get the second batch.
    var bucketAfterSecondRelease = midnight.minusHours(12);

    MockHttpServletResponse responseWithPublishedAfter =
            mockMvc
                    .perform(
                            get("/v2UMA/gaen/exposed?lastKeyBundleTag=" + midnight.minusDays(8).getTimestamp())
                                    .header("User-Agent", "MockMVC")
                                    .param(
                                            "publishedafter", Long.toString(bucketAfterSecondRelease.getTimestamp())))
                    .andExpect(status().is2xxSuccessful())
                    .andReturn()
                    .getResponse();

    // must contain 15 keys: 5 from the second insert and 10 random keys
    verifyZipResponse(responseWithPublishedAfter, 15);
  }

  @Test
  public void testHello() throws Exception {
    MockHttpServletResponse response =
        mockMvc
            .perform(get("/v2UMA/gaen"))
            .andExpect(status().is2xxSuccessful())
            .andReturn()
            .getResponse();

    assertNotNull(response);
    assertEquals("Hello from DP3T WS GAEN V2-UMA", response.getContentAsString());
  }

  @Test
  public void testUploadTodaysKeyWillBeReleasedTomorrowWithV1Upload() throws Exception {
    testUploadTodaysKeyWillBeReleasedTomorrow(false);
  }

  @Test
  public void testUploadTodaysKeyWillBeReleasedTomorrowWithV2Upload() throws Exception {
    testUploadTodaysKeyWillBeReleasedTomorrow(true);
  }

  private void testUploadTodaysKeyWillBeReleasedTomorrow(boolean useV2Upload) throws Exception {
    var now = UTCInstant.now();
    List<GaenKey> keys = new ArrayList<>();
    for (int i = 0; i < 30; i++) {
      var tmpKey = new GaenKey();
      tmpKey.setRollingStartNumber((int) now.atStartOfDay().minusDays(i).get10MinutesSince1970());
      var keyData = String.format("testKey32Bytes%02d", i);
      tmpKey.setKeyData(Base64.getEncoder().encodeToString(keyData.getBytes("UTF-8")));
      tmpKey.setRollingPeriod(144);
      tmpKey.setFake(0);
      tmpKey.setTransmissionRiskLevel(0);
      keys.add(tmpKey);
    }

    Object uploadPayload;
    if (useV2Upload) {
      GaenV2UploadKeysRequest exposeeRequest = new GaenV2UploadKeysRequest();
      exposeeRequest.setGaenKeys(keys);
      uploadPayload = exposeeRequest;
    } else {
      GaenRequest exposeeRequest = new GaenRequest();
      exposeeRequest.setGaenKeys(keys);
      exposeeRequest.setDelayedKeyDate((int) now.atStartOfDay().get10MinutesSince1970());
      uploadPayload = exposeeRequest;
    }

    String token = createToken(now.plusMinutes(5));
    MvcResult responseAsync =
        mockMvc
            .perform(
                post(useV2Upload ? "/v2UMA/gaen/exposed" : "/v1/gaen/exposed")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + token)
                    .header("User-Agent", androidUserAgent)
                    .content(json(uploadPayload)))
            .andExpect(request().asyncStarted())
            .andReturn();
    mockMvc.perform(asyncDispatch(responseAsync)).andExpect(status().isOk());

    MockHttpServletResponse response =
        mockMvc
            .perform(get("/v2UMA/gaen/exposed").header("User-Agent", androidUserAgent))
            .andExpect(status().is(204))
            .andReturn()
            .getResponse();

    String keyBundleTag = response.getHeader("x-key-bundle-tag");

    // at 01:00 UTC we expect all the keys but the one from yesterday, because this one might still
    // be accepted by client apps
    Clock oneAMTomorrow =
        Clock.fixed(
            now.atStartOfDay().plusDays(1).plusHours(1).plusSeconds(0).getInstant(),
            ZoneOffset.UTC);

    try (var timeLock = UTCInstant.setClock(oneAMTomorrow)) {
      response =
          mockMvc
              .perform(
                  get("/v2UMA/gaen/exposed?lastKeyBundleTag=" + keyBundleTag)
                      .header("User-Agent", androidUserAgent))
              .andExpect(status().isOk())
              .andReturn()
              .getResponse();
      verifyZipResponse(response, 14);
    }
    keyBundleTag = response.getHeader("x-key-bundle-tag");

    // at 04:00 UTC we expect to get the 1 key of yesterday
    Clock fourAMTomorrow =
        Clock.fixed(
            now.atStartOfDay().plusDays(1).plusHours(4).plusSeconds(0).getInstant(),
            ZoneOffset.UTC);

    try (var timeLock = UTCInstant.setClock(fourAMTomorrow)) {
      response =
          mockMvc
              .perform(
                  get("/v2UMA/gaen/exposed?lastKeyBundleTag=" + keyBundleTag)
                      .header("User-Agent", androidUserAgent))
              .andExpect(status().isOk())
              .andReturn()
              .getResponse();

      verifyZipResponse(response, 1);
    }
    keyBundleTag = response.getHeader("x-key-bundle-tag");

    // at 08:00 UTC we do not expect any further keys and thus expect a 204 status
    Clock eightAMTomorrow =
        Clock.fixed(
            now.atStartOfDay().plusDays(1).plusHours(8).plusSeconds(0).getInstant(),
            ZoneOffset.UTC);

    try (var timeLock = UTCInstant.setClock(eightAMTomorrow)) {
      response =
          mockMvc
              .perform(
                  get("/v2UMA/gaen/exposed?lastKeyBundleTag=" + keyBundleTag)
                      .header("User-Agent", androidUserAgent))
              .andExpect(status().is(204))
              .andReturn()
              .getResponse();
    }
  }

  @Test
  public void testUploadWithShortenedRollingPeriodWithV1Upload() throws Exception {
    testUploadWithShortenedRollingPeriod(false);
  }

  @Test
  public void testUploadWithShortenedRollingPeriodWithV2Upload() throws Exception {
    testUploadWithShortenedRollingPeriod(true);
  }

  private void testUploadWithShortenedRollingPeriod(boolean useV2Upload) throws Exception {
    // set keyReleasTime to 14:10 UTC
    var keyReleaseTime = UTCInstant.now().atStartOfDay().plusHours(14).plusMinutes(10);
    List<GaenKey> keys = new ArrayList<>();
    for (int i = 0; i < 30; i++) {
      var tmpKey = new GaenKey();
      tmpKey.setRollingStartNumber(
          (int) keyReleaseTime.atStartOfDay().minusDays(i).get10MinutesSince1970());
      var keyData = String.format("testKey32Bytes%02d", i);
      tmpKey.setKeyData(Base64.getEncoder().encodeToString(keyData.getBytes("UTF-8")));
      tmpKey.setRollingPeriod(144);
      tmpKey.setFake(0);
      tmpKey.setTransmissionRiskLevel(0);
      keys.add(tmpKey);
    }
    // set shortened rolling period for first key
    keys.get(0).setRollingPeriod(85);

    Object uploadPayload;
    if (useV2Upload) {
      GaenV2UploadKeysRequest exposeeRequest = new GaenV2UploadKeysRequest();
      exposeeRequest.setGaenKeys(keys);
      uploadPayload = exposeeRequest;
    } else {
      GaenRequest exposeeRequest = new GaenRequest();
      exposeeRequest.setGaenKeys(keys);
      exposeeRequest.setDelayedKeyDate((int) keyReleaseTime.atStartOfDay().get10MinutesSince1970());
      uploadPayload = exposeeRequest;
    }

    String token = createToken(UTCInstant.now().plusMinutes(5));

    String keyBundleTag;

    System.out.println(json(uploadPayload));

    try (var timeLock =
        UTCInstant.setClock(Clock.fixed(keyReleaseTime.getInstant(), ZoneOffset.UTC))) {
      MvcResult responseAsync =
          mockMvc
              .perform(
                  post(useV2Upload ? "/v2UMA/gaen/exposed" : "/v1/gaen/exposed")
                      .contentType(MediaType.APPLICATION_JSON)
                      .header("Authorization", "Bearer " + token)
                      .header("User-Agent", androidUserAgent)
                      .content(json(uploadPayload)))
              .andExpect(request().asyncStarted())
              .andReturn();
      mockMvc.perform(asyncDispatch(responseAsync)).andExpect(status().isOk());

      MockHttpServletResponse response =
          mockMvc
              .perform(get("/v2UMA/gaen/exposed").header("User-Agent", androidUserAgent))
              .andExpect(status().is(204))
              .andReturn()
              .getResponse();

      keyBundleTag = response.getHeader("x-key-bundle-tag");
    }

    // at 16:00 UTC we expect all the keys but the one from today, because this one might still
    // be accepted by client apps
    Clock fourPMToday =
        Clock.fixed(
            keyReleaseTime.atStartOfDay().plusHours(16).plusSeconds(0).getInstant(),
            ZoneOffset.UTC);

    try (var timeLock = UTCInstant.setClock(fourPMToday)) {
      MockHttpServletResponse response =
          mockMvc
              .perform(
                  get("/v2UMA/gaen/exposed?lastKeyBundleTag=" + keyBundleTag)
                      .header("User-Agent", androidUserAgent))
              .andExpect(status().isOk())
              .andReturn()
              .getResponse();
      verifyZipResponse(response, 14);
      keyBundleTag = response.getHeader("x-key-bundle-tag");
    }

    // at 18:00 UTC we expect the one key from today, because this one was delayed
    Clock sixPMToday =
        Clock.fixed(
            keyReleaseTime.atStartOfDay().plusHours(18).plusSeconds(0).getInstant(),
            ZoneOffset.UTC);

    try (var timeLock = UTCInstant.setClock(sixPMToday)) {
      MockHttpServletResponse response =
          mockMvc
              .perform(
                  get("/v2UMA/gaen/exposed?lastKeyBundleTag=" + keyBundleTag)
                      .header("User-Agent", androidUserAgent))
              .andExpect(status().isOk())
              .andReturn()
              .getResponse();
      verifyZipResponse(response, 1);
      keyBundleTag = response.getHeader("x-key-bundle-tag");
    }

    // at 20:00 UTC we expect no further keys
    Clock eightPMToday =
        Clock.fixed(
            keyReleaseTime.atStartOfDay().plusHours(20).plusSeconds(0).getInstant(),
            ZoneOffset.UTC);

    try (var timeLock = UTCInstant.setClock(eightPMToday)) {
      MockHttpServletResponse response =
          mockMvc
              .perform(
                  get("/v2UMA/gaen/exposed?lastKeyBundleTag=" + keyBundleTag)
                      .header("User-Agent", androidUserAgent))
              .andExpect(status().is(204))
              .andReturn()
              .getResponse();
    }
  }

  /**
   * Creates keysPerDay for every day: lastDay, lastDay-1, ..., lastDay - daysBack + 1
   *  @param lastDay of the created keys
   * @param daysBack of the key creation, counted including the lastDay
   * @param keysPerDay that will be created for every day
   * @param receivedAt as sent to the DB
   * @param debug if true, inserts the keys in the debug table.
   */
  private void insertNKeysPerDay(
          UTCInstant lastDay, int daysBack, int keysPerDay, UTCInstant receivedAt, boolean debug) {
    SecureRandom random = new SecureRandom();
    List<GaenKey> keys = null;
    for (int d = 0; d < daysBack; d++) {
      var currentKeyDate = lastDay.minusDays(d);
      int currentRollingStartNumber = (int) currentKeyDate.get10MinutesSince1970();
      keys = new ArrayList<>();
      for (int n = 0; n < keysPerDay; n++) {
        GaenKey key = new GaenKey();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        key.setKeyData(Base64.getEncoder().encodeToString(keyBytes));
        key.setRollingPeriod(144);
        key.setRollingStartNumber(currentRollingStartNumber);
        key.setTransmissionRiskLevel(1);
        key.setFake(0);
        keys.add(key);
      }
      if (debug) {
        testGaenDataService.upsertExposeesDebug(keys, receivedAt);
      } else {
        testGaenDataService.upsertExposees(keys, receivedAt);
      }
    }
  }

}
