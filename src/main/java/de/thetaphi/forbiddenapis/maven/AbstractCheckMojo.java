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

package de.thetaphi.forbiddenapis.maven;

import static de.thetaphi.forbiddenapis.Checker.Option.DISABLE_CLASSLOADING_CACHE;
import static de.thetaphi.forbiddenapis.Checker.Option.FAIL_ON_MISSING_CLASSES;
import static de.thetaphi.forbiddenapis.Checker.Option.FAIL_ON_UNRESOLVABLE_SIGNATURES;
import static de.thetaphi.forbiddenapis.Checker.Option.FAIL_ON_VIOLATION;
import static de.thetaphi.forbiddenapis.Checker.Option.IGNORE_SIGNATURES_OF_MISSING_CLASSES;

import java.io.File;
import java.io.IOException;
import java.lang.annotation.RetentionPolicy;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.codehaus.plexus.util.DirectoryScanner;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;

import de.thetaphi.forbiddenapis.Checker;
import de.thetaphi.forbiddenapis.Constants;
import de.thetaphi.forbiddenapis.ForbiddenApiException;
import de.thetaphi.forbiddenapis.Logger;
import de.thetaphi.forbiddenapis.ParseException;

/**
 * Base class for forbiddenapis Mojos.
 * @since 1.0
 */
public abstract class AbstractCheckMojo extends AbstractMojo implements Constants {

  /**
   * Lists all files, which contain signatures and comments for forbidden API calls.
   * The signatures are resolved against the compile classpath.
   * @since 1.0
   */
  @Parameter(required = false)
  private File[] signaturesFiles;

  /**
   * Lists all Maven artifacts, which contain signatures and comments for forbidden API calls.
   * The artifact needs to be specified like a Maven dependency. Resolution is not transitive.
   * You can refer to plain text Maven artifacts ({@code type="txt"}, e.g., with a separate {@code classifier}):
   * <pre>
   * &lt;signaturesArtifact&gt;
   *   &lt;groupId&gt;org.apache.foobar&lt;/groupId&gt;
   *   &lt;artifactId&gt;example&lt;/artifactId&gt;
   *   &lt;version&gt;1.0&lt;/version&gt;
   *   &lt;classifier&gt;signatures&lt;/classifier&gt;
   *   &lt;type&gt;txt&lt;/type&gt;
   * &lt;/signaturesArtifact&gt;
   * </pre>
   * Alternatively,  refer to signatures files inside JAR artifacts. In that case, the additional
   * parameter {@code path} has to be given:
   * <pre>
   * &lt;signaturesArtifact&gt;
   *   &lt;groupId&gt;org.apache.foobar&lt;/groupId&gt;
   *   &lt;artifactId&gt;example&lt;/artifactId&gt;
   *   &lt;version&gt;1.0&lt;/version&gt;
   *   &lt;type&gt;jar&lt;/type&gt;
   *   &lt;path&gt;path/inside/jar/file/signatures.txt&lt;/path&gt;
   * &lt;/signaturesArtifact&gt;
   * </pre>
   * <p>The signatures are resolved against the compile classpath.
   * @since 2.0
   */
  @Parameter(required = false)
  private SignaturesArtifact[] signaturesArtifacts;

  /**
   * Gives a multiline list of signatures, inline in the pom.xml. Use an XML CDATA section to do that!
   * The signatures are resolved against the compile classpath.
   * @since 1.0
   */
  @Parameter(required = false)
  private String signatures;

  /**
   * Specifies <a href="bundled-signatures.html">built-in signatures</a> files (e.g., deprecated APIs for specific Java versions,
   * unsafe method calls using default locale, default charset,...)
   * @since 1.0
   */
  @Parameter(required = false)
  private String[] bundledSignatures;

  /** 
   * Specifies a list of forbidden API signatures for which violations should lead to a warning only (i.e. not fail the build). This takes precedence over {@link #failOnViolation}.
   * In order to be effective the signature must be given in either {@link #bundledSignatures}, {@link #signaturesFiles}, {@link #signaturesArtifacts}, or {@link #signatures}.
   * @since 3.9
   */
  @Parameter(required = false)
  private String[] signaturesWithSeverityWarn;
  
  /** 
   * Specifies a list of forbidden API signatures for which violations should not be reported at all (i.e. neither fail the build nor appear in the logs). This takes precedence over {@link #failOnViolation} and {@link #signaturesWithSeverityWarn}.
   * In order to be effective the signature must be given in either {@link #bundledSignatures}, {@link #signaturesFiles}, {@link #signaturesArtifacts}, or {@link #signatures}.
   * @since 3.9
   */
  @Parameter(required = false)
  private String[] signaturesWithSeveritySuppress;

  /**
   * Fail the build, if the bundled ASM library cannot read the class file format
   * of the runtime library or the runtime library cannot be discovered.
   * @since 1.0
   */
  @Parameter(required = false, defaultValue = "false")
  private boolean failOnUnsupportedJava;
  
  /**
   * Fail the build, if a class referenced in the scanned code is missing. This requires
   * that you pass the whole classpath including all dependencies to this Mojo
   * (Maven does this by default).
   * @since 1.0
   */
  @Parameter(required = false, defaultValue = "true")
  private boolean failOnMissingClasses;
  
  /**
   * Fail the build if a signature is not resolving. If this parameter is set to
   * to false, then such signatures are ignored. Defaults to {@code true}.
   * <p>When disabling this setting, the task still prints a warning to inform the user about
   * broken signatures. This cannot be disabled. There is a second setting
   * {@link #ignoreSignaturesOfMissingClasses} that can be used to silently ignore
   * signatures that refer to methods or field in classes that are not on classpath,
   * e.g. This is useful in multi-module Maven builds where a common set of signatures is used,
   * that are not part of every sub-modules dependencies.
   * @see #ignoreSignaturesOfMissingClasses
   * @deprecated The setting {@code failOnUnresolvableSignatures} was deprecated and will be removed in next version. Use {@link #ignoreSignaturesOfMissingClasses} instead.
   * @since 1.4
   */
  @Deprecated
  @Parameter(required = false, defaultValue = "true")
  private boolean failOnUnresolvableSignatures;
  
  /**
   * If a class is missing while parsing signatures files, all methods and fields from this
   * class are silently ignored. This is useful in multi-module Maven
   * projects where only some modules have the dependency to which the signature file(s) apply.
   * This settings prints no warning at all, so verify the signatures at least once with
   * full dependencies.
   * Defaults to {@code false}.
   * @since 3.0
   */
  @Parameter(required = false, defaultValue = "false")
  private boolean ignoreSignaturesOfMissingClasses;


  /**
   * Fail the build if violations have been found. Defaults to {@code true}.
   * @since 2.0
   */
  @Parameter(required = false, property="forbiddenapis.failOnViolation", defaultValue = "true")
  private boolean failOnViolation;

  /**
   * Disable the internal JVM classloading cache when getting bytecode from
   * the classpath. This setting slows down checks, but <em>may</em> work around
   * issues with other Mojos, that do not close their class loaders.
   * If you get {@code FileNotFoundException}s related to non-existent JAR entries
   * you can try to work around using this setting.
   * @since 2.2
   */
  @Parameter(required = false, defaultValue = "false")
  private boolean disableClassloadingCache;

  /**
   * The default compiler target version used to expand references to bundled JDK signatures.
   * E.g., if you use "jdk-deprecated", it will expand to this version.
   * This setting should be identical to the target version used in the compiler plugin.
   * @since 1.0
   */
  @Parameter(required = false, defaultValue = "${maven.compiler.target}")
  private String targetVersion;

  /**
   * The default compiler release version used to expand references to bundled JDK signatures.
   * E.g., if you use "jdk-deprecated", it will expand to this version.
   * This setting should be identical to the release version used in the compiler plugin starting with Java 9.
   * If given, this setting is used in preference to {@link #targetVersion}.
   * @since 3.1
   */
  @Parameter(required = false, defaultValue = "${maven.compiler.release}")
  private String releaseVersion;

  /**
   * List of <a href="https://ant.apache.org/manual/dirtasks.html#patterns">Ant patterns</a> which must match all relative class paths to be considered.
   * All relative class paths matching one or more of the given patterns and not matching any of the ones from {@link #excludes} are considered.
   * The given paths are relative to {@code classesDirectory}.
   * Can be changed to e.g. exclude several files (using {@link #excludes}).
   * The default is a single include with pattern <code>**&#47;*.class</code>.
   * @see #excludes
   * @since 1.0
   */
  @Parameter(required = false)
  private String[] includes;

  /**
   * List of <a href="https://ant.apache.org/manual/dirtasks.html#patterns">Ant patterns</a>.
   * All relative class paths matching one or more of the given patterns are skipped.
   * The given paths are relative to {@code classesDirectory}.
   *
   * @see #includes
   * @since 1.0
   */
  @Parameter(required = false)
  private String[] excludes;

  /**
   * List of a custom Java annotations (full class names) that are used in the checked
   * code to suppress errors. Those annotations must have at least
   * {@link RetentionPolicy#CLASS}. They can be applied to classes, their methods,
   * or fields. By default, {@code @de.thetaphi.forbiddenapis.SuppressForbidden}
   * can always be used, but needs the {@code forbidden-apis.jar} file in classpath
   * of compiled project, which may not be wanted.
   * Instead of a full class name, a glob pattern may be used (e.g.,
   * {@code **.SuppressForbidden}).
   * @since 1.8
   */
  @Parameter(required = false)
  private String[] suppressAnnotations;

  /**
   * Skip entire check. Most useful on the command line via "-Dforbiddenapis.skip=true".
   * @since 1.6
   */
  @Parameter(required = false, property="forbiddenapis.skip", defaultValue="false")
  private boolean skip;

  /** The project packaging (pom, jar, etc.). */
  @Parameter(defaultValue = "${project.packaging}", readonly = true, required = true)
  private String packaging;

  @Component
  private RepositorySystem repoSystem;

  @Parameter(defaultValue = "${repositorySystemSession}", readonly = true, required = true)
  private RepositorySystemSession repoSession;

  @Parameter(defaultValue = "${project.remoteProjectRepositories}", readonly = true, required = true)
  private List<RemoteRepository> projectRepos;

  /** provided by the concrete Mojos for compile and test classes processing */
  protected abstract List<String> getClassPathElements();
  
  /** provided by the concrete Mojos for compile and test classes processing */
  protected abstract File getClassesDirectory();

  /** gets overridden for test, because it uses testTargetVersion as optional name to override */
  protected String getTargetVersion() {
    return (releaseVersion != null) ? releaseVersion : targetVersion;
  }
  
  private File resolveSignaturesArtifact(SignaturesArtifact signaturesArtifact) throws ArtifactResolutionException {
    final Artifact artifact = signaturesArtifact.createArtifact();
    ArtifactRequest req = new ArtifactRequest(artifact, projectRepos, null);
    ArtifactResult resolutionResult = repoSystem.resolveArtifact(repoSession, req);
    return resolutionResult.getArtifact().getFile();
  }
  
  private String encodeUrlPath(String path) {
    try {
      // hack to encode the URL path by misusing URI class:
      return new URI(null, path, null).toASCIIString();
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
  }
  
  private URL createJarUrl(File f, String jarPath) throws MalformedURLException {
    final URL fileUrl = f.toURI().toURL();
    final URL jarBaseUrl = new URL("jar", null, fileUrl.toExternalForm() + "!/");
    return new URL(jarBaseUrl, encodeUrlPath(jarPath));
  }

  @Override
  public void execute() throws MojoExecutionException {
    final Logger log = new Logger() {
      @Override
      public void error(String msg) {
        getLog().error(msg);
      }
      
      @Override
      public void warn(String msg) {
        getLog().warn(msg);
      }
      
      @Override
      public void info(String msg) {
        getLog().info(msg);
      }
      
      @Override
      public void debug(String msg) {
        getLog().debug(msg);
      }
    };
    
    if (skip) {
      log.info("Skipping forbidden-apis checks.");
      return;
    }
    
    // In multi-module projects, one may want to configure the plugin in the parent/root POM.
    // However, it should not be executed for this type of POMs.
    if ("pom".equals(packaging)) {
      log.info("Skipping execution for packaging \"" + packaging + "\"");
      return;
    }

    // set default param:
    if (includes == null) includes = new String[] {"**/*.class"};
    
    final List<String> cp = getClassPathElements();
    final URL[] urls = new URL[cp.size()];
    final StringBuilder humanClasspath = new StringBuilder();
    try {
      int i = 0;
      for (final String cpElement : cp) {
        urls[i++] = new File(cpElement).toURI().toURL();
        if (humanClasspath.length() > 0) {
          humanClasspath.append(File.pathSeparatorChar);
        }
        humanClasspath.append(cpElement);
      }
      assert i == urls.length;
    } catch (MalformedURLException e) {
      throw new MojoExecutionException("Failed to build classpath.", e);
    }
    log.debug("Classpath: " + humanClasspath);

    URLClassLoader urlLoader = null;
    final ClassLoader loader = (urls.length > 0) ?
      (urlLoader = URLClassLoader.newInstance(urls, ClassLoader.getSystemClassLoader())) :
      ClassLoader.getSystemClassLoader();
    
    try {
      final EnumSet<Checker.Option> options = EnumSet.noneOf(Checker.Option.class);
      if (failOnMissingClasses) options.add(FAIL_ON_MISSING_CLASSES);
      if (failOnViolation) options.add(FAIL_ON_VIOLATION);
      if (failOnUnresolvableSignatures) {
        options.add(FAIL_ON_UNRESOLVABLE_SIGNATURES);
      } else {
        log.warn(DEPRECATED_WARN_FAIL_ON_UNRESOLVABLE_SIGNATURES);
      }
      if (ignoreSignaturesOfMissingClasses) options.add(IGNORE_SIGNATURES_OF_MISSING_CLASSES);
      if (disableClassloadingCache) options.add(DISABLE_CLASSLOADING_CACHE);
      final Checker checker = new Checker(log, loader, options);
      
      if (!checker.isSupportedJDK) {
        final String msg = String.format(Locale.ENGLISH, 
          "Your Java runtime (%s %s) is not supported by the forbiddenapis MOJO. Please run the checks with a supported JDK!",
          System.getProperty("java.runtime.name"), System.getProperty("java.runtime.version"));
        if (failOnUnsupportedJava) {
          throw new MojoExecutionException(msg);
        } else {
          log.warn(msg);
          return;
        }
      }
      
      if (suppressAnnotations != null) {
        for (String a : suppressAnnotations) {
          checker.addSuppressAnnotation(a);
        }
      }
      
      log.info("Scanning for classes to check...");
      final File classesDirectory = getClassesDirectory();
      if (!classesDirectory.exists()) {
        log.info("Classes directory does not exist, forbiddenapis check skipped: " + classesDirectory);
        return;
      }
      final DirectoryScanner ds = new DirectoryScanner();
      ds.setBasedir(classesDirectory);
      ds.setCaseSensitive(true);
      ds.setIncludes(includes);
      ds.setExcludes(excludes);
      ds.addDefaultExcludes();
      ds.scan();
      final String[] files = ds.getIncludedFiles();
      if (files.length == 0) {
        log.info(String.format(Locale.ENGLISH,
          "No classes found in '%s' (includes=%s, excludes=%s), forbiddenapis check skipped.",
          classesDirectory.toString(), Arrays.toString(includes), Arrays.toString(excludes)));
        return;
      }
      
      try {
        if (bundledSignatures != null) {
          String targetVersion = getTargetVersion();
          if ("".equals(targetVersion)) targetVersion = null;
          if (targetVersion == null) {
            log.warn("The 'targetVersion' and 'targetRelease' parameters or " +
              "'${maven.compiler.target}' and '${maven.compiler.release}' properties are missing. " +
              "Trying to read bundled JDK signatures without compiler target. " +
              "You have to explicitly specify the version in the resource name.");
          }
          for (String bs : new LinkedHashSet<>(Arrays.asList(bundledSignatures))) {
            checker.addBundledSignatures(bs, targetVersion);
          }
        }
        
        final Set<File> sigFiles = new LinkedHashSet<>();
        final Set<URL> sigUrls = new LinkedHashSet<>();
        if (signaturesFiles != null) {
          sigFiles.addAll(Arrays.asList(signaturesFiles));
        }

        if (signaturesArtifacts != null) {
          for (final SignaturesArtifact artifact : signaturesArtifacts) {
            final File f = resolveSignaturesArtifact(artifact);
            if (artifact.path != null) {
              if (f.isDirectory()) {
                // if Maven did not yet jarred the artifact, it returns the classes
                // folder of the foreign Maven project, just use that one:
                sigFiles.add(new File(f, artifact.path));
              } else {
                sigUrls.add(createJarUrl(f, artifact.path));
              }
            } else {
              sigFiles.add(f);
            }
          }
        }
        for (final File f : sigFiles) {
          checker.parseSignaturesFile(f);
        }
        for (final URL u : sigUrls) {
          checker.parseSignaturesFile(u);
        }
        final String sig = (signatures != null) ? signatures.trim() : null;
        if (sig != null && sig.length() != 0) {
          checker.parseSignaturesString(sig);
        }
        if (signaturesWithSeverityWarn != null) {
          checker.setSignaturesSeverity(Arrays.asList(signaturesWithSeverityWarn), Checker.ViolationSeverity.WARNING);
        }
        if (signaturesWithSeveritySuppress != null) {
          checker.setSignaturesSeverity(Arrays.asList(signaturesWithSeveritySuppress), Checker.ViolationSeverity.SUPPRESS);
        }
      } catch (IOException ioe) {
        throw new MojoExecutionException("IO problem while reading files with API signatures.", ioe);
      } catch (ParseException pe) {
        throw new MojoExecutionException("Parsing signatures failed: " + pe.getMessage(), pe);
      } catch (ArtifactResolutionException e) {
        throw new MojoExecutionException("Problem while resolving Maven artifact.", e);
      }

      if (checker.hasNoSignatures()) {
        if (checker.noSignaturesFilesParsed()) {
          throw new MojoExecutionException("No signatures were added to mojo; use parameters 'signatures', 'bundledSignatures', 'signaturesFiles',  and/or 'signaturesArtifacts' to define those!");
        } else {
          log.info("Skipping execution because no API signatures are available.");
          return;
        }
      }

      try {
        checker.addClassesToCheck(classesDirectory, files);
      } catch (IOException ioe) {
        throw new MojoExecutionException("Failed to load one of the given class files.", ioe);
      }

      try {
        checker.run();
      } catch (ForbiddenApiException fae) {
        throw new MojoExecutionException(fae.getMessage(), fae.getCause());
      }
    } finally {
      // Close the classloader to free resources:
      try {
        if (urlLoader != null) urlLoader.close();
      } catch (IOException ioe) {
        log.warn("Cannot close classloader: ".concat(ioe.toString()));
      }
    }
  }
  
}
