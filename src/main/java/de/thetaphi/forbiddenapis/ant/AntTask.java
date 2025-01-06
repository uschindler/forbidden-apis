/*
 * (C) Copyright Uwe Schindler (Generics Policeman) and others.
 * Parts of this work are licensed to the Apache Software Foundation (ASF)
 * under one or more contributor license agreements.
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

package de.thetaphi.forbiddenapis.ant;

import static de.thetaphi.forbiddenapis.Checker.Option.*;

import org.apache.maven.plugins.annotations.Parameter;
import org.apache.tools.ant.AntClassLoader;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.ProjectComponent;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.types.Path;
import org.apache.tools.ant.types.FileList;
import org.apache.tools.ant.types.FileSet;
import org.apache.tools.ant.types.Reference;
import org.apache.tools.ant.types.Resource;
import org.apache.tools.ant.types.ResourceCollection;
import org.apache.tools.ant.types.resources.FileResource;
import org.apache.tools.ant.types.resources.StringResource;
import org.apache.tools.ant.types.resources.Union;

import de.thetaphi.forbiddenapis.Checker;
import de.thetaphi.forbiddenapis.Constants;
import de.thetaphi.forbiddenapis.ForbiddenApiException;
import de.thetaphi.forbiddenapis.Logger;
import de.thetaphi.forbiddenapis.ParseException;

import java.io.IOException;
import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Locale;

/**
 * Task to check if a set of class files contains calls to forbidden APIs
 * from a given classpath and list of API signatures (either inline or as pointer to files).
 * In contrast to other ANT tasks, this tool does only visit the given classpath
 * and the system classloader, not ANT's class loader.
 */
public class AntTask extends Task implements Constants {

  private final Union classFiles = new Union();
  private final Union apiSignatures = new Union();
  private final Collection<BundledSignaturesType> bundledSignatures = new LinkedHashSet<>();
  private final Collection<SuppressAnnotationType> suppressAnnotations = new LinkedHashSet<>();
  private final Collection<String> signaturesWithSeverityWarn = new LinkedHashSet<>();;
  private final Collection<String> signaturesWithSeveritySuppress = new LinkedHashSet<>();;

  private Path classpath = null;
  
  private boolean failOnUnsupportedJava = false;
  private boolean restrictClassFilename = true;
  private boolean failOnMissingClasses = true;
  private boolean failOnUnresolvableSignatures = true;
  private boolean ignoreSignaturesOfMissingClasses = false;
  private boolean failOnViolation = true;
  private boolean ignoreEmptyFileset = false;
  private String targetVersion = null;
  private boolean disableClassloadingCache = false;
    
  @Override
  public void execute() throws BuildException {
    final Logger log = new Logger() {
      @Override
      public void error(String msg) {
        log(msg, Project.MSG_ERR);
      }
      
      @Override
      public void warn(String msg) {
        // ANT has no real log levels printed, so prefix with "WARNING":
        log("WARNING: ".concat(msg), Project.MSG_WARN);
      }
      
      @Override
      public void info(String msg) {
        log(msg, Project.MSG_INFO);
      }
      
      @Override
      public void debug(String msg) {
        log(msg, Project.MSG_DEBUG);
      }
    };
    
    AntClassLoader antLoader = null;
    try {
      final ClassLoader loader;
      if (classpath != null) {
        classpath.setProject(getProject());
        loader = antLoader = getProject().createClassLoader(ClassLoader.getSystemClassLoader(), classpath);
        antLoader.setParentFirst(true); // use default classloader delegation
        log.debug("Classpath: " + classpath.toString());
      } else {
        loader = ClassLoader.getSystemClassLoader();
      }
      classFiles.setProject(getProject());
      apiSignatures.setProject(getProject());
      
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
          "Your Java runtime (%s %s) is not supported by <%s/>. Please run the checks with a supported JDK!",
          System.getProperty("java.runtime.name"), System.getProperty("java.runtime.version"), getTaskName());
        if (failOnUnsupportedJava) {
          throw new BuildException(msg);
        } else {
          log.warn(msg);
          return;
        }
      }
      
      for (final SuppressAnnotationType a : suppressAnnotations) {
        checker.addSuppressAnnotation(a.getClassname());
      }
      
      try {
        for (BundledSignaturesType bs : bundledSignatures) {
          final String name = bs.getName();
          if (name == null) {
            throw new BuildException("<bundledSignatures/> must have the mandatory attribute 'name' referring to a bundled signatures file.");
          }
          String targetVersion = this.targetVersion;
          if (bs.getTargetVersion() != null) {
            if (!name.startsWith("jdk-")) {
              throw new ParseException("Cannot supply a targetVersion for non-JDK signatures.");
            }
            targetVersion = bs.getTargetVersion();
          }
          if (targetVersion == null  && name.startsWith("jdk-")) {
            log.warn("The 'targetVersion' parameter is missing. " +
              "Trying to read bundled JDK signatures without compiler target. " +
              "You have to explicitly specify the version in the resource name.");
          }
          checker.addBundledSignatures(name, targetVersion);
        }
        
        @SuppressWarnings("unchecked")
        final Iterator<Resource> iter = apiSignatures.iterator();
        while (iter.hasNext()) {
          final Resource r = iter.next();
          if (r instanceof StringResource) {
            final String s = ((StringResource) r).getValue();
            if (s != null && s.trim().length() > 0) {
              checker.parseSignaturesString(s);
            }
          } else {
            checker.parseSignaturesFile(r.getInputStream(), r.toString());
          }
        }
        if (!signaturesWithSeverityWarn.isEmpty()) {
          checker.setSignaturesSeverity(signaturesWithSeverityWarn, Checker.ViolationSeverity.WARNING);
        }
        if (!signaturesWithSeveritySuppress.isEmpty()) {
          checker.setSignaturesSeverity(signaturesWithSeveritySuppress, Checker.ViolationSeverity.SUPPRESS);
        }
      } catch (IOException ioe) {
        throw new BuildException("IO problem while reading files with API signatures: " + ioe.getMessage(), ioe);
      } catch (ParseException pe) {
        throw new BuildException("Parsing signatures failed: " + pe.getMessage(), pe);
      }
        
      if (checker.hasNoSignatures()) {
        if (checker.noSignaturesFilesParsed()) {
          throw new BuildException("No signatures were added to task; use signaturesFile=, <signatures*/>, <bundledSignatures/> or inner text to define those!");
        } else {
          log.info("Skipping execution because no API signatures are available.");
          return;
        }
      }

      log.info("Loading classes to check...");
      try {
        @SuppressWarnings("unchecked")
        final Iterator<Resource> iter = classFiles.iterator();
        boolean foundClass = false;
        while (iter.hasNext()) {
          final Resource r = iter.next();
          final String name = r.getName();
          if (restrictClassFilename && name != null && !name.endsWith(".class")) {
            continue;
          }
          checker.addClassToCheck(r.getInputStream(), r.getName());
          foundClass = true;
        }
        if (!foundClass) {
          if (ignoreEmptyFileset) {
            log.info("Resource collection of class files is empty. Scanned 0 class files.");
            return;
          } else {
            throw new BuildException("There is no <fileset/> or other resource collection given, or the collection does not contain any class files to check.");
          }
        }
      } catch (IOException ioe) {
        throw new BuildException("Failed to load one of the given class files: " + ioe.getMessage(), ioe);
      }

      try {
        checker.run();
      } catch (ForbiddenApiException fae) {
        throw new BuildException(fae.getMessage(), fae.getCause());
      }
    } finally {
      if (antLoader != null) antLoader.cleanup();
    }
  }
  
  /** Set of class files to check */
  public void add(ResourceCollection rc) {
    classFiles.add(rc);
  }
  
  /** Sets a directory as base for class files. The implicit pattern '**&#47;*.class' is used to only scan class files. */
  public void setDir(File dir) {
    final FileSet fs = new FileSet();
    fs.setProject(getProject());
    fs.setDir(dir);
    // needed if somebody sets restrictClassFilename=false:
    fs.setIncludes("**/*.class");
    classFiles.add(fs);
  }
  
  private <T extends ProjectComponent & ResourceCollection> T addSignaturesResource(T res) {
    res.setProject(getProject());
    apiSignatures.add(res);
    return res;
  }
  
  /** Set of files with API signatures as <signaturesFileSet/> nested element */
  public FileSet createSignaturesFileSet() {
    return addSignaturesResource(new FileSet());
  }

  /** List of files with API signatures as <signaturesFileList/> nested element */
  public FileList createSignaturesFileList() {
    return addSignaturesResource(new FileList());
  }

  /** Single file with API signatures as <signaturesFile/> nested element */
  public FileResource createSignaturesFile() {
    return addSignaturesResource(new FileResource());
  }

  /** Collection of arbitrary Ant resources or {@code <bundled/>} elements. */
  public SignaturesResources createSignatures() {
    return addSignaturesResource(new SignaturesResources(this));
  }

  /** A file with API signatures signaturesFile= attribute */
  public void setSignaturesFile(File file) {
    createSignaturesFile().setFile(file);
  }
  
  /** Support for API signatures list as nested text */
  public void addText(String text) {
    addSignaturesResource(new StringResource(text));
  }

  /** Creates a bundled signatures instance */
  public BundledSignaturesType createBundledSignatures() {
    final BundledSignaturesType s = new BundledSignaturesType();
    s.setProject(getProject());
    bundledSignatures.add(s);
    return s;
  }

  /** A bundled signatures name */
  public void setBundledSignatures(String name) {
    createBundledSignatures().setName(name);
  }
  
  /** 
   * A list of forbidden API signatures for which violations should not be reported at all (i.e. neither fail the build nor appear in the logs). This takes precedence over {@link #failOnViolation} and {@link #signaturesWithSeverityWarn}.
   * In order to be effective the signature must be given in either {@link #bundledSignatures}, {@link #signaturesFiles}, {@link #signaturesArtifacts}, or {@link #signatures}.
   * @since 3.9
   */
  public void setSignaturesWithSeverityWarn(String signature) {
      signaturesWithSeverityWarn.add(signature);
  }

  /** A list of forbidden API signatures for which violations should not be reported at all (i.e. neither fail the build nor appear in the logs). This takes precedence over {@link #failOnViolation} and {@link #signaturesWithSeverityWarn}.
   * In order to be effective the signature must be given in either {@link #bundledSignatures}, {@link #signaturesFiles}, {@link #signaturesArtifacts}, or {@link #signatures}.
   * @since 3.9
   */
  public void setSignaturesWithSeveritySuppress(String signature) {
    signaturesWithSeveritySuppress.add(signature);
  }

  /** Creates a instance of an annotation class name that suppresses error reporting in classes/methods/fields. */
  public SuppressAnnotationType createSuppressAnnotation() {
    final SuppressAnnotationType s = new SuppressAnnotationType();
    s.setProject(getProject());
    suppressAnnotations.add(s);
    return s;
  }

  /** Class name of annotation that suppresses error reporting in classes/methods/fields. */
  public void setSuppressAnnotation(String classname) {
    createSuppressAnnotation().setClassname(classname);
  }
  
  /** Classpath as classpath= attribute */
  public void setClasspath(Path classpath) {
    createClasspath().append(classpath);
  }

  /** Classpath as classpathRef= attribute */
  public void setClasspathRef(Reference r) {
    createClasspath().setRefid(r);
  }

  /** Classpath as <classpath/> nested element */
  public Path createClasspath() {
    if (this.classpath == null) {
        this.classpath = new Path(getProject());
    }
    return this.classpath.createPath();
  }
  
  /**
   * Fail the build, if the bundled ASM library cannot read the class file format
   * of the runtime library or the runtime library cannot be discovered.
   * Defaults to {@code false}. 
   */
  public void setFailOnUnsupportedJava(boolean failOnUnsupportedJava) {
    this.failOnUnsupportedJava = failOnUnsupportedJava;
  }

  /**
   * Fail the build, if a referenced class is missing. This requires
   * that you pass the whole classpath including all dependencies.
   * If you don't have all classes in the filesets, the application classes
   * must be reachable through this classpath, too.
   * Defaults to {@code true}. 
   */
  public void setFailOnMissingClasses(boolean failOnMissingClasses) {
    this.failOnMissingClasses = failOnMissingClasses;
  }

  /**
   * Fail the build if a signature is not resolving. If this parameter is set to
   * to false, then such signatures are ignored. Defaults to {@code true}.
   * <p>When disabling this setting, the task still prints a warning to inform the user about
   * broken signatures. This cannot be disabled. There is a second setting
   * {@link #setIgnoreMissingSignaturesClasses()} that can be used to silently ignore
   * signatures that refer to methods or field in classes that are not on classpath,
   * e.g. This is useful in multi-module builds where a common set of signatures is used,
   * that are not part of every sub-modules dependencies.
   * @see #setIgnoreMissingSignaturesClasses()
   * @deprecated Use {@link #setIgnoreSignaturesOfMissingClasses(boolean)} instead.
   */
  @Deprecated
  public void setFailOnUnresolvableSignatures(boolean failOnUnresolvableSignatures) {
    this.failOnUnresolvableSignatures = failOnUnresolvableSignatures;
  }

  /**
   * If a class is missing while parsing signatures files, all methods and fields from this
   * class are silently ignored. This is useful in multi-module
   * projects where only some modules have the dependency to which the signature file(s) apply.
   * This settings prints no warning at all, so verify the signatures at least once with
   * full dependencies.
   * Defaults to {@code false}.
   * @since 3.0
   */
  public void setIgnoreSignaturesOfMissingClasses(boolean ignoreSignaturesOfMissingClasses) {
    this.ignoreSignaturesOfMissingClasses = ignoreSignaturesOfMissingClasses;
  }
  
  /** Automatically restrict resource names included to files with a name ending in '.class'.
   * This makes filesets easier, as the includes="**&#47;*.class" is not needed.
   * Defaults to {@code true}.
   */
  public void setRestrictClassFilename(boolean restrictClassFilename) {
    this.restrictClassFilename = restrictClassFilename;
  }

  /** Ignore empty fileset/resource collection.
   * Defaults to {@code false}.
   */
  public void setIgnoreEmptyFileSet(boolean ignoreEmptyFileset) {
    this.ignoreEmptyFileset = ignoreEmptyFileset;
  }

  /**
   * Fail the build if violations have been found. If this parameter is set to {@code false},
   * then the build will continue even if violations have been found.
   * Defaults to {@code true}.
   */
  public void setFailOnViolation(boolean failOnViolation) {
    this.failOnViolation = failOnViolation;
  }
  
  /**
   * The default compiler target version used to expand references to bundled JDK signatures.
   * E.g., if you use "jdk-deprecated", it will expand to this version.
   * This setting should be identical to the target version used in the compiler task.
   * Defaults to {@code null}.
   * @since 2.1
   */
  public void setTargetVersion(String targetVersion) {
    this.targetVersion = targetVersion;
  }
  
  /**
   * Disable the internal JVM classloading cache when getting bytecode from
   * the classpath. This setting slows down checks, but <em>may</em> work around
   * issues with other tasks, that do not close their class loaders.
   * If you get {@code FileNotFoundException}s related to non-existent JAR entries
   * you can try to work around using this setting.
   * The default is {@code false}.
   * @since 2.2
   */
  public void setDisableClassloadingCache(boolean disableClassloadingCache) {
    this.disableClassloadingCache = disableClassloadingCache;
  }
}
