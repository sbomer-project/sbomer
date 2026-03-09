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
package org.jboss.sbomer.cli.test.utils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.redhat.red.build.koji.model.json.BuildExtraInfo;
import com.redhat.red.build.koji.model.json.RemoteSourcesExtraInfo;
import com.redhat.red.build.koji.model.json.TypeInfoExtraInfo;
import com.redhat.red.build.koji.model.json.util.KojiObjectMapper;
import com.redhat.red.build.koji.model.xmlrpc.KojiBuildInfo;

public final class KojiBuildInfoFactory {
    private static final KojiObjectMapper MAPPER = new KojiObjectMapper();

    public static KojiBuildInfo withRemoteSources(KojiBuildInfo buildInfo, String... names) {
        List<RemoteSourcesExtraInfo> infos = Arrays.stream(names).map(name -> {
            RemoteSourcesExtraInfo info = new RemoteSourcesExtraInfo();
            info.setName(name);
            return info;
        }).toList();
        TypeInfoExtraInfo typeInfoExtraInfo = new TypeInfoExtraInfo();
        typeInfoExtraInfo.setRemoteSourcesExtraInfo(infos);
        BuildExtraInfo buildExtraInfo = new BuildExtraInfo();
        buildExtraInfo.setTypeInfo(typeInfoExtraInfo);
        Map<String, Object> extra = MAPPER.convertValue(buildExtraInfo, new TypeReference<>() {
        });
        buildInfo.setExtra(extra);
        return buildInfo;
    }
}
