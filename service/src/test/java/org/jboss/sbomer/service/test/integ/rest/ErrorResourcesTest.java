/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.sbomer.service.test.integ.rest;

import static org.mockito.Mockito.doThrow;

import org.hamcrest.CoreMatchers;
import org.hamcrest.Matchers;
import org.jboss.sbomer.service.feature.sbom.service.SbomService;
import org.jboss.sbomer.service.test.utils.umb.TestUmbProfile;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.junit.mockito.InjectSpy;
import io.restassured.RestAssured;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAllowedException;
import jakarta.ws.rs.NotAuthorizedException;

/**
 * Ensures that we can handle errors properly.
 */
@QuarkusTest
@TestProfile(TestUmbProfile.class)
class ErrorResourcesTest {

    @InjectSpy
    SbomService sbomService;

    @Test
    void testHandlingNotFoundResource() {
        RestAssured.given()
                .when()
                .get("/api/alph/sms/doesnotexist")
                .then()
                .statusCode(404)
                .body("resource", CoreMatchers.is("/api/alph/sms/doesnotexist"))
                .body("errorId", CoreMatchers.isA(String.class))
                .body("error", CoreMatchers.is("Not Found"))
                .body("message", CoreMatchers.is("Requested resource '/api/alph/sms/doesnotexist' was not found"))
                .body("$", Matchers.not(Matchers.hasKey("errors")));
    }

    @Test
    void testHandlingNotFoundSbom() {
        RestAssured.given()
                .when()
                .get("/api/v1beta1/manifests/doesnotexist")
                .then()
                .statusCode(404)
                .body("resource", CoreMatchers.is("/api/v1beta1/manifests/doesnotexist"))
                .body("errorId", CoreMatchers.isA(String.class))
                .body("error", CoreMatchers.is("Not Found"))
                .body("message", CoreMatchers.is("Manifest with provided identifier: 'doesnotexist' couldn't be found"))
                .body("$", Matchers.not(Matchers.hasKey("errors")));
    }

    @Test
    void testHandlingUnauthorized() {
        // This doesn't make sense, but what we want to test is handling of any NotAuthorizedException
        doThrow(NotAuthorizedException.class).when(sbomService).get("unauthorized");

        RestAssured.given()
                .when()
                .get("/api/v1beta1/manifests/unauthorized")
                .then()
                .statusCode(401)
                .body("resource", CoreMatchers.is("/api/v1beta1/manifests/unauthorized"))
                .body("errorId", CoreMatchers.isA(String.class))
                .body("error", CoreMatchers.is("Unauthorized"))
                .body(
                        "message",
                        CoreMatchers.is("Access to '/api/v1beta1/manifests/unauthorized' resource is not authorized!"))
                .body("$", Matchers.not(Matchers.hasKey("errors")));
    }

    @Test
    void testHandlingForbidden() {
        // This doesn't make sense, but what we want to test is handling of any ForbiddenException
        doThrow(ForbiddenException.class).when(sbomService).get("forbidden");

        RestAssured.given()
                .when()
                .get("/api/v1beta1/manifests/forbidden")
                .then()
                .statusCode(403)
                .body("resource", CoreMatchers.is("/api/v1beta1/manifests/forbidden"))
                .body("errorId", CoreMatchers.isA(String.class))
                .body("error", CoreMatchers.is("Forbidden"))
                .body("message", CoreMatchers.is("Access to '/api/v1beta1/manifests/forbidden' resource is forbidden!"))
                .body("$", Matchers.not(Matchers.hasKey("errors")));
    }

    @Test
    void testHandlingNotAllowed() {
        // This doesn't make sense, but what we want to test is handling of any NotAllowedException
        doThrow(NotAllowedException.class).when(sbomService).get("notallowed");

        RestAssured.given()
                .when()
                .get("/api/v1beta1/manifests/notallowed")
                .then()
                .statusCode(405)
                .body("resource", CoreMatchers.is("/api/v1beta1/manifests/notallowed"))
                .body("errorId", CoreMatchers.isA(String.class))
                .body("error", CoreMatchers.is("Method Not Allowed"))
                .body(
                        "message",
                        CoreMatchers.is(
                                "Requesting resource '/api/v1beta1/manifests/notallowed' using 'GET' method is not allowed. Please consult API documentation."))
                .body("$", Matchers.not(Matchers.hasKey("errors")));
    }

    @Test
    void testIllegalParameters() {
        RestAssured.given()
                .when()
                .get("/api/v1beta1/manifests?sort=123")
                .then()
                .statusCode(400)
                .body("resource", CoreMatchers.is("/api/v1beta1/manifests"))
                .body("errorId", CoreMatchers.isA(String.class))
                .body("error", CoreMatchers.is("Bad Request"))
                .body(
                        "message",
                        CoreMatchers.startsWith(
                                "An error occurred while parsing the RSQL query, please make sure you use correct syntax: "))
                .body("$", Matchers.not(Matchers.hasKey("errors")));
    }

    @Test
    void testDefaultExceptionMapper() {
        // This doesn't make sense, but what we want to test handling of an exception that we don't handle
        // explicitly
        doThrow(new RuntimeException("Opps, bad things happened")).when(sbomService).get("Runtime");

        RestAssured.given()
                .when()
                .get("/api/v1beta1/manifests/Runtime")
                .then()
                .log()
                .all()
                .statusCode(500)
                .body("resource", CoreMatchers.is("/api/v1beta1/manifests/Runtime"))
                .body("errorId", CoreMatchers.isA(String.class))
                .body("error", CoreMatchers.is("Internal Server Error"))
                .body(
                        "message",
                        CoreMatchers.is(
                                "An error occurred while processing your request, please contact administrator providing the 'errorId'"))
                .body("$", Matchers.not(Matchers.hasKey("errors")));
    }

    @Test
    void testInvalidRSQL() {
        RestAssured.given()
                .when()
                .get("/api/v1beta1/manifests?query=asd")
                .then()
                .statusCode(400)
                .body("resource", CoreMatchers.is("/api/v1beta1/manifests"))
                .body("errorId", CoreMatchers.isA(String.class))
                .body("error", CoreMatchers.is("Bad Request"))
                .body(
                        "message",
                        CoreMatchers.startsWith(
                                "An error occurred while parsing the RSQL query, please make sure you use correct syntax: "))
                .body("$", Matchers.not(Matchers.hasKey("errors")));
    }
}
