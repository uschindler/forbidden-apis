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

package de.thetaphi.forbiddenapis;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.JarURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.regex.Pattern;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Type;

import de.thetaphi.forbiddenapis.Checker.ViolationSeverity;

/**
 * Forbidden APIs checker class.
 */
public final class Checker implements RelatedClassLookup, Constants {
  
  public static enum Option {
    FAIL_ON_MISSING_CLASSES,
    FAIL_ON_VIOLATION,
    FAIL_ON_UNRESOLVABLE_SIGNATURES,
    IGNORE_SIGNATURES_OF_MISSING_CLASSES,
    DISABLE_CLASSLOADING_CACHE
  }

  public enum ViolationSeverity {
      ERROR, WARNING, INFO, DEBUG, SUPPRESS
  }

  public final boolean isSupportedJDK;
  
  private final long start;
  private final NavigableSet<String> runtimePaths;
    
  final Logger logger;
  
  final ClassLoader loader;
  final java.lang.reflect.Method method_Class_getModule, method_Module_getName;
  final EnumSet<Option> options;
  
  /** Classes to check: key is the binary name (dotted) */
  final Map<String,ClassMetadata> classesToCheck = new HashMap<>();
  /** Cache of loaded classes: key is the binary name (dotted) */
  final Map<String,ClassMetadata> classpathClassCache = new HashMap<>();
  
  /** Related classes (binary name, dotted) which were not found while looking up
   * class metadata [referenced (super)classes, interfaces,...] */
  final Set<String> missingClasses = new TreeSet<>();
  
  final Signatures forbiddenSignatures;
  
  /** descriptors (not internal names) of all annotations that suppress */
  final Set<String> suppressAnnotations = new LinkedHashSet<>();
    
  public Checker(Logger logger, ClassLoader loader, Option... options) {
    this(logger, loader, (options.length == 0) ? EnumSet.noneOf(Option.class) : EnumSet.copyOf(Arrays.asList(options)));
  }
  
  public Checker(Logger logger, ClassLoader loader, EnumSet<Option> options) {
    this.logger = logger;
    this.loader = loader;
    this.options = options;
    this.start = System.currentTimeMillis();
    
    // default (always available)
    addSuppressAnnotation(SuppressForbidden.class);
    
    boolean isSupportedJDK = false;
    
    // Try to figure out entry points to Java 9+ module system (Jigsaw)
    java.lang.reflect.Method method_Class_getModule, method_Module_getName;
    try {
      method_Class_getModule = Class.class.getMethod("getModule");
      method_Module_getName = method_Class_getModule
          .getReturnType().getMethod("getName");
      isSupportedJDK = true;
      logger.debug("Detected Java 9 or later with module system.");
    } catch (NoSuchMethodException e) {
      method_Class_getModule = method_Module_getName = null;
    }
    this.method_Class_getModule = method_Class_getModule;
    this.method_Module_getName = method_Module_getName;
    
    final NavigableSet<String> runtimePaths = new TreeSet<>();
    
    // fall back to legacy behavior:
    if (!isSupportedJDK) {
      try {
        final URL objectClassURL = loader.getResource(AsmUtils.getClassResourceName(Object.class.getName()));
        if (objectClassURL != null && "jrt".equalsIgnoreCase(objectClassURL.getProtocol())) {
          // this is Java 9+ allowing direct access to .class file resources - we do not need to deal with modules!
          isSupportedJDK = true;
          logger.debug("Detected Java 9 or later with JRT file system.");
        } else {
          String javaHome = System.getProperty("java.home");
          if (javaHome != null) {
            javaHome = new File(javaHome).getCanonicalPath();
            if (!javaHome.endsWith(File.separator)) {
              javaHome += File.separator;
            }
            runtimePaths.add(javaHome);
          }
          // Scan the runtime's bootclasspath, too! This is needed for
          // some JDKs that may have the rt.jar outside ${java.home}!
          final RuntimeMXBean rb = ManagementFactory.getRuntimeMXBean();
          if (rb.isBootClassPathSupported()) {
            final String cp = rb.getBootClassPath();
            final StringTokenizer st = new StringTokenizer(cp, File.pathSeparator);
            while (st.hasMoreTokens()) {
              File f = new File(st.nextToken().trim());
              if (f.isFile()) {
                f = f.getParentFile();
              }
              if (f.exists()) {
                String fp = f.getCanonicalPath();
                if (!fp.endsWith(File.separator)) {
                  fp += File.separator;
                }
                runtimePaths.add(fp);
              }
            }
          }
          isSupportedJDK = !runtimePaths.isEmpty();
          if (isSupportedJDK) {
            logger.debug("Detected classical classpath-based JDK @ " + runtimePaths);
          } else {
            logger.warn("Boot classpath appears to be empty or ${java.home} not defined; marking runtime as not suppported.");
          }
        }
      } catch (IOException ioe) {
        logger.warn("Cannot scan boot classpath and ${java.home} due to IO exception; marking runtime as not suppported: " + ioe);
        isSupportedJDK = false;
        runtimePaths.clear();
      }
    }
    this.runtimePaths = runtimePaths;
    // logger.info("Runtime paths: " + runtimePaths);
    
    if (isSupportedJDK) {
      try {
        isSupportedJDK = getClassFromClassLoader(Object.class.getName()).isRuntimeClass;
        if (!isSupportedJDK) {
          logger.warn("Bytecode of java.lang.Object does not seem to come from runtime library; marking runtime as not suppported.");
        }
      } catch (IllegalArgumentException iae) {
        logger.warn("Bundled version of ASM cannot parse bytecode of java.lang.Object class; marking runtime as not suppported.");
        isSupportedJDK = false;
      } catch (ClassNotFoundException cnfe) {
        logger.warn("Bytecode or Class<?> instance of java.lang.Object not found; marking runtime as not suppported.");
        isSupportedJDK = false;
      } catch (IOException ioe) {
        logger.warn("IOException while loading java.lang.Object class from classloader; marking runtime as not suppported: " + ioe);
        isSupportedJDK = false;
      }
    }
    
    // finally set the latest value to final field:
    this.isSupportedJDK = isSupportedJDK;
    
    // make signatures ready for parse:
    this.forbiddenSignatures = new Signatures(this);
  }
  
  /** Loads the class from Java9's module system and uses reflection to get methods and fields. */
  private ClassMetadata loadClassFromJigsaw(String classname) throws IOException {
    if (method_Class_getModule == null || method_Module_getName == null) {
      return null; // not Jigsaw Module System
    }
    
    final Class<?> clazz;
    final String moduleName;
    try {
      clazz = Class.forName(classname, false, loader);
      final Object module = method_Class_getModule.invoke(clazz);
      moduleName = (String) method_Module_getName.invoke(module);
    } catch (Exception e) {
      return null; // not found
    }
    
    return new ClassMetadata(clazz, AsmUtils.isRuntimeModule(moduleName));
  }
  
  private boolean isRuntimePath(URL url) throws IOException {
    if (!"file".equalsIgnoreCase(url.getProtocol())) {
      return false;
    }
    try {
      final String path = new File(url.toURI()).getCanonicalPath();
      final String lookup = runtimePaths.floor(path);
      return lookup != null && path.startsWith(lookup);
    } catch (URISyntaxException e) {
      // should not happen, but if it's happening, it's definitely not a below our paths
      return false;
    }
  }
  
  private boolean isRuntimeClass(URLConnection conn) throws IOException {
    final URL url = conn.getURL();
    if (isRuntimePath(url)) {
       return true;
    } else if ("jar".equalsIgnoreCase(url.getProtocol()) && conn instanceof JarURLConnection) {
      final URL jarUrl = ((JarURLConnection) conn).getJarFileURL();
      return isRuntimePath(jarUrl);
    } else if ("jrt".equalsIgnoreCase(url.getProtocol())) {
      // all 'jrt:' URLs refer to a module in the Java 9+ runtime (see http://openjdk.java.net/jeps/220)
      return AsmUtils.isRuntimeModule(AsmUtils.getModuleName(url));
    }
    return false;
  }
  
  /** Reads a class (binary name) from the given {@link ClassLoader}. If not found there, falls back to the list of classes to be checked. */
  @Override
  public ClassMetadata getClassFromClassLoader(final String clazz) throws ClassNotFoundException,IOException {
    if (classpathClassCache.containsKey(clazz)) {
      final ClassMetadata c = classpathClassCache.get(clazz);
      if (c == null) {
        throw new ClassNotFoundException(clazz);
      }
      return c;
    } else {
      final URL url = loader.getResource(AsmUtils.getClassResourceName(clazz));
      if (url != null) {
        final URLConnection conn = url.openConnection();
        final boolean isRuntimeClass = isRuntimeClass(conn);
        if (!isRuntimeClass && options.contains(Option.DISABLE_CLASSLOADING_CACHE)) {
          conn.setUseCaches(false);
        }
        final ClassReader cr;
        try (final InputStream in = conn.getInputStream()) {
          cr = AsmUtils.readAndPatchClass(in);
        } catch (IllegalArgumentException iae) {
          // if class is too new for this JVM, we try to load it as Class<?> via Jigsaw
          // (only if it's a runtime class):
          if (isRuntimeClass) {
            final ClassMetadata c = loadClassFromJigsaw(clazz);
            if (c != null) {
              classpathClassCache.put(clazz, c);
              return c;
            }
          }
          throw new IllegalArgumentException(String.format(Locale.ENGLISH,
              "The class file format of '%s' (loaded from location '%s') is too recent to be parsed by ASM.",
              clazz, url.toExternalForm()));
        }
        final ClassMetadata c = new ClassMetadata(cr, isRuntimeClass, false);
        classpathClassCache.put(clazz, c);
        return c;
      } else {
        final ClassMetadata c = loadClassFromJigsaw(clazz);
        if (c != null) {
          classpathClassCache.put(clazz, c);
          return c;
        }
      }
      // try to get class from our list of classes we are checking:
      final ClassMetadata c = classesToCheck.get(clazz);
      if (c != null) {
        classpathClassCache.put(clazz, c);
        return c;
      }
      // all failed => the class does not exist!
      classpathClassCache.put(clazz, null);
      throw new ClassNotFoundException(clazz);
    }
  }
  
  @Override
  public ClassMetadata lookupRelatedClass(String internalName, String internalNameOrig) {
    final Type type = Type.getObjectType(internalName);
    if (type.getSort() != Type.OBJECT) {
      return null;
    }
    try {
      // use binary name, so we need to convert:
      return getClassFromClassLoader(type.getClassName());
    } catch (ClassNotFoundException cnfe) {
      final String origClassName = Type.getObjectType(internalNameOrig).getClassName();
      if (options.contains(Option.FAIL_ON_MISSING_CLASSES)) {
        throw new RelatedClassLoadingException(cnfe, origClassName);
      } else {
        logger.debug(String.format(Locale.ENGLISH,
            "Class '%s' cannot be loaded (while looking up details about referenced class '%s').",
            type.getClassName(), origClassName));
        missingClasses.add(type.getClassName());
        return null;
      }
    } catch (IOException ioe) {
      throw new RelatedClassLoadingException(ioe, Type.getObjectType(internalNameOrig).getClassName());
    } catch (RuntimeException re) {
      if (AsmUtils.isExceptionInAsmClassReader(re)) {
        throw new RelatedClassLoadingException(re, Type.getObjectType(internalNameOrig).getClassName());
      }
      throw re;
    }
  }
  
  /** Reads a list of bundled API signatures from classpath. */
  public void addBundledSignatures(String name, String jdkTargetVersion) throws IOException,ParseException {
    forbiddenSignatures.addBundledSignatures(name, jdkTargetVersion);
  }
  
  /** Reads a list of API signatures. Closes the Reader when done (on Exception, too)! */
  public void parseSignaturesFile(InputStream in, String name) throws IOException,ParseException {
    forbiddenSignatures.parseSignaturesStream(in, name);
  }
  
  /** Reads a list of API signatures from the given URL. */
  public void parseSignaturesFile(URL url) throws IOException,ParseException {
    parseSignaturesFile(url.openStream(), url.toString());
  }
  
  /** Reads a list of API signatures from the given file. */
  public void parseSignaturesFile(File f) throws IOException,ParseException {
    parseSignaturesFile(new FileInputStream(f), f.toString());
  }
    
  /** Reads a list of API signatures from a String. */
  public void parseSignaturesString(String signatures) throws IOException,ParseException {
    forbiddenSignatures.parseSignaturesString(signatures);
  }
  
  /** Returns if there are any signatures. */
  public boolean hasNoSignatures() {
    return forbiddenSignatures.hasNoSignatures();
  }
  
  /** Returns if no signatures files / inline signatures were parsed */
  public boolean noSignaturesFilesParsed() {
    return forbiddenSignatures.noSignaturesFilesParsed();
  }
  
  /** Adjusts the severity of a specific signature. */
  public void setSignaturesSeverity(Collection<String> signatures, ViolationSeverity severity) throws ParseException, IOException {
    forbiddenSignatures.setSignaturesSeverity(signatures, severity);
  }
  
  /** Parses and adds a class from the given stream to the list of classes to check. Closes the stream when parsed (on Exception, too)! Does not log anything. */
  public void addClassToCheck(final InputStream in, String name) throws IOException {
    final ClassReader reader;
    try (final InputStream in_ = in) {
      reader = AsmUtils.readAndPatchClass(in_);
    } catch (IllegalArgumentException iae) {
      throw new IllegalArgumentException(String.format(Locale.ENGLISH,
          "The class file format of '%s' is too recent to be parsed by ASM.", name));
    }
    final ClassMetadata metadata = new ClassMetadata(reader, false, true);
    classesToCheck.put(metadata.getBinaryClassName(), metadata);
  }
  
  /** Parses and adds a class from the given file to the list of classes to check. Does not log anything. */
  public void addClassToCheck(File f) throws IOException {
    addClassToCheck(new FileInputStream(f), f.toString());
  }

  /** Parses and adds a multiple class files. */
  public void addClassesToCheck(Iterable<File> files) throws IOException {
    logger.info("Loading classes to check...");
    for (final File f : files) {
      addClassToCheck(f);
    }
  }

  /** Parses and adds a multiple class files. */
  public void addClassesToCheck(File... files) throws IOException {
    addClassesToCheck(Arrays.asList(files));
  }

  /** Parses and adds a multiple class files. */
  public void addClassesToCheck(File basedir, Iterable<String> relativeNames) throws IOException {
    logger.info("Loading classes to check...");
    for (final String f : relativeNames) {
      addClassToCheck(new File(basedir, f));
    }
  }

  /** Parses and adds a multiple class files. */
  public void addClassesToCheck(File basedir, String... relativeNames) throws IOException {
    addClassesToCheck(basedir, Arrays.asList(relativeNames));
  }

  /** Adds the given annotation class for suppressing errors. */
  public void addSuppressAnnotation(Class<? extends Annotation> anno) {
    suppressAnnotations.add(anno.getName());
  }
  
  /** Adds suppressing annotation name in binary form (dotted). It may also be a glob pattern. The class name is not checked for existence. */
  public void addSuppressAnnotation(String annoName) {
    suppressAnnotations.add(annoName);
  }
  
  /** Parses a class and checks for valid method invocations */
  private int checkClass(ClassMetadata c, Pattern suppressAnnotationsPattern) throws ForbiddenApiException {
    final String className = c.getBinaryClassName();
    final ClassScanner scanner = new ClassScanner(c, this, forbiddenSignatures, suppressAnnotationsPattern, options.contains(Option.FAIL_ON_VIOLATION)); 
    try {
      c.getReader().accept(scanner, ClassReader.SKIP_FRAMES);
    } catch (RelatedClassLoadingException rcle) {
      final Exception cause = rcle.getException();
      final StringBuilder msg = new StringBuilder()
          .append("Check for forbidden API calls failed while scanning class '")
          .append(className)
          .append('\'');
      final String source = scanner.getSourceFile();
      if (source != null) {
        msg.append(" (").append(source).append(')');
      }
      msg.append(": ").append(cause);
      msg.append(" (while looking up details about referenced class '").append(rcle.getClassName()).append("')");
      assert cause != null && (cause instanceof IOException || cause instanceof ClassNotFoundException || cause instanceof RuntimeException);
      throw new ForbiddenApiException(msg.toString(), cause);
    } catch (RuntimeException re) {
      if (AsmUtils.isExceptionInAsmClassReader(re)) {
        final StringBuilder msg = new StringBuilder()
            .append("Failed to parse class '")
            .append(className)
            .append('\'');
        final String source = scanner.getSourceFile();
        if (source != null) {
          msg.append(" (").append(source).append(')');
        }
        msg.append(": ").append(re);
        throw new ForbiddenApiException(msg.toString(), re);
      }
      // else rethrow (it's occuring in our code):
      throw re;
    }
    final List<ForbiddenViolation> violations = scanner.getSortedViolations();
    final Pattern splitter = Pattern.compile(Pattern.quote(ForbiddenViolation.SEPARATOR));
    int numErrors = 0;
    for (final ForbiddenViolation v : violations) {
      if (v.severity == ViolationSeverity.ERROR) {
        numErrors++;
      }
      for (final String line : splitter.split(v.format(className, scanner.getSourceFile()))) {
        switch (v.severity) {
        case DEBUG:
          logger.debug(line);
          break;
        case INFO:
          logger.info(line);
          break;
        case WARNING:
          logger.warn(line);
          break;
        case ERROR:
          logger.error(line);
          break;
        default:
          break;
        }
      }
    }
    return numErrors;
  }
  
  public void run() throws ForbiddenApiException {
    logger.info("Scanning classes for violations...");
    int errors = 0;
    final Pattern suppressAnnotationsPattern = AsmUtils.glob2Pattern(suppressAnnotations.toArray(new String[suppressAnnotations.size()]));
    for (final ClassMetadata c : classesToCheck.values()) {
      errors += checkClass(c, suppressAnnotationsPattern);
    }
    
    if (!missingClasses.isEmpty() ) {
      logger.warn("While scanning classes to check, the following referenced classes were not found on classpath (this may miss some violations):");
      logger.warn(AsmUtils.formatClassesAbbreviated(missingClasses));
    }
    
    final String message = String.format(Locale.ENGLISH, 
        "Scanned %d class file(s) for forbidden API invocations (in %.2fs), %d error(s).",
        classesToCheck.size(), (System.currentTimeMillis() - start) / 1000.0, errors);
    if (options.contains(Option.FAIL_ON_VIOLATION) && errors > 0) {
      logger.error(message);
      throw new ForbiddenApiException("Check for forbidden API calls failed, see log.");
    } else {
      logger.info(message);
    }
  }
}
