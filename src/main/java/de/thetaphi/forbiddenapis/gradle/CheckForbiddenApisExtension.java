/*
 * (C) Copyright Uwe Schindler (Generics Policeman) and others.
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

package de.thetaphi.forbiddenapis.gradle;

import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.gradle.api.Project;
import org.gradle.api.file.FileCollection;

/**
 * Extension for the ForbiddenApis Gradle Task to store defaults.
 * For description of the properties refer to the {@link CheckForbiddenApis}
 * task documentation.
 * @since 2.0
 */
public class CheckForbiddenApisExtension {
  
  public CheckForbiddenApisExtension(Project project) {
    signaturesFiles = project.files();
  }
  
  public FileCollection signaturesFiles;
  public Set<URL> signaturesURLs = new LinkedHashSet<>();
  public List<String> signatures = new ArrayList<>();
  public Set<String> bundledSignatures = new LinkedHashSet<>(),
    suppressAnnotations = new LinkedHashSet<>(),
    signaturesWithSeveritySuppress = new LinkedHashSet<>(),
    signaturesWithSeverityWarn = new LinkedHashSet<>();
  public boolean failOnUnsupportedJava = false,
    failOnMissingClasses = true,
    failOnUnresolvableSignatures = true,
    ignoreFailures = false,
    ignoreSignaturesOfMissingClasses = false,
    disableClassloadingCache = ForbiddenApisPluginBase.DEFAULT_DISABLE_CLASSLOADING_CACHE;
  
}
