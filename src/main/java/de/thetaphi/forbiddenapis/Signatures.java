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

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.objectweb.asm.Type;
import org.objectweb.asm.commons.Method;

import de.thetaphi.forbiddenapis.Checker.Option;
import de.thetaphi.forbiddenapis.Checker.ViolationSeverity;

/** Utility class that is used to get an overview of all fields and implemented
 * methods of a class. It make the signatures available as Sets. */
public final class Signatures implements Constants {
  
  private static final String BUNDLED_PREFIX = "@includeBundled ";
  private static final String DEFAULT_MESSAGE_PREFIX = "@defaultMessage ";
  private static final String IGNORE_UNRESOLVABLE_LINE = "@ignoreUnresolvable";
  private static final String IGNORE_MISSING_CLASSES_LINE = "@ignoreMissingClasses";
  private static final String WILDCARD_ARGS = "**";
  private static final Pattern PATTERN_WILDCARD_ARGS = Pattern.compile(String.format(Locale.ROOT, "%s\\s*%s\\s*%s",
      Pattern.quote("("), Pattern.quote(WILDCARD_ARGS), Pattern.quote(")")));

  private static enum UnresolvableReporting {
    FAIL(true) {
      @Override
      public void parseFailed(Logger logger, String message, String signature) throws ParseException {
        throw new ParseException(String.format(Locale.ENGLISH, "%s while parsing signature: %s", message, signature));
      }
    },
    WARNING(false) {
      @Override
      public void parseFailed(Logger logger, String message, String signature) throws ParseException {
        logger.warn(String.format(Locale.ENGLISH, "%s while parsing signature: %s [signature ignored]", message, signature));
      }
    },
    SILENT(true) {
      @Override
      public void parseFailed(Logger logger, String message, String signature) throws ParseException {
        // keep silent
      }
    };
    
    private UnresolvableReporting(boolean reportClassNotFound) {
      this.reportClassNotFound = reportClassNotFound;
    }
    
    public final boolean reportClassNotFound;
    public abstract void parseFailed(Logger logger, String message, String signature) throws ParseException;
  }
  
  private final RelatedClassLookup lookup;
  private final Logger logger;
  private final boolean failOnUnresolvableSignatures, ignoreSignaturesOfMissingClasses;

  /** Key is used to lookup forbidden signature in following formats. Keys are generated by the corresponding
   * {@link #getKey(String)} (classes), {@link #getKey(String, Method)} (methods),
   * {@link #getKey(String, String)} (fields) call.
   */
  final Map<String,String> signatures = new HashMap<>();
  
  /** set of patterns of forbidden classes */
  final Set<ClassPatternRule> classPatterns = new LinkedHashSet<>();
  
  /** Key is used to lookup forbidden signature in following formats. Keys are generated by the corresponding
   * {@link #getKey(String)} (classes), {@link #getKey(String, Method)} (methods),
   * {@link #getKey(String, String)} (fields) call.
   */
  final Map<String, ViolationSeverity> severityPerSignature = new HashMap<>();
  final Map<Pattern, ViolationSeverity> severityPerClassPattern = new HashMap<>();

  /** if enabled, the bundled signature to enable heuristics for detection of non-portable runtime calls is used */
  private boolean forbidNonPortableRuntime = false;
  
  /** number of files that were interpreted as signatures file. If 0, no (bundled) signatures files were added at all */
  private int numberOfFiles = 0;

  /** determines default severity for violations if no severity on signature level is overridden. true = ERROR, false = WARNING */
  private boolean failOnViolation;

  public Signatures(Checker checker) {
    this(checker, checker.logger, checker.options.contains(Option.IGNORE_SIGNATURES_OF_MISSING_CLASSES), checker.options.contains(Option.FAIL_ON_UNRESOLVABLE_SIGNATURES), checker.options.contains(Option.FAIL_ON_VIOLATION));
  }
  
  public Signatures(RelatedClassLookup lookup, Logger logger, boolean ignoreSignaturesOfMissingClasses, boolean failOnUnresolvableSignatures, boolean failOnViolation) {
    this.lookup = lookup;
    this.logger = logger;
    this.ignoreSignaturesOfMissingClasses = ignoreSignaturesOfMissingClasses;
    this.failOnUnresolvableSignatures = failOnUnresolvableSignatures;
    this.failOnViolation = failOnViolation;
  }
  
  static String getKey(String internalClassName) {
    return "c\000" + internalClassName;
  }
  
  static String getKey(String internalClassName, String field) {
    return "f\000" + internalClassName + '\000' + field;
  }
  
  static String getKey(String internalClassName, Method method) {
    return "m\000" + internalClassName + '\000' + method;
  }
  
  /** Adds the method signature to the list of disallowed methods. The Signature is checked against the given ClassLoader. */
  private void addSignature(final String line, final String defaultMessage, final UnresolvableReporting report,
      final boolean localIgnoreMissingClasses, final Set<String> missingClasses) throws ParseException,IOException {
    String message = null;
    String signature;
    int p = line.indexOf('@');
    if (p >= 0) {
      signature = line.substring(0, p).trim();
      message = line.substring(p + 1).trim();
    } else {
      signature = line;
      message = defaultMessage;
    }
    if (line.isEmpty()) {
      throw new ParseException("Empty signature");
    }
    if (message != null && message.isEmpty()) {
        message = null;
    }
    // create printout message:
    final String printout = (message != null) ? (signature + " [" + message + "]") : signature;
    Collection<String> keys = getKeys(report, localIgnoreMissingClasses, missingClasses, signature);
    if (keys != null) {
        for (String key : keys) {
            if (key.startsWith("c\000") || key.startsWith("f\000") || key.startsWith("m\000")) {
                signatures.put(key, printout);
            }
            else {
                classPatterns.add(new ClassPatternRule(key, message));
            }
        }
    }
  }

private Collection<String> getKeys(final UnresolvableReporting report, final boolean localIgnoreMissingClasses, final Set<String> missingClasses,
        final String signature) throws ParseException, IOException {
    final String clazz;
    final String field;
    final Method method;
    int p;
    p = signature.indexOf('#');
    if (p >= 0) {
      clazz = signature.substring(0, p);
      final String methodOrField = signature.substring(p + 1);
      p = methodOrField.indexOf('(');
      if (p >= 0) {
        if (p == 0) {
          throw new ParseException("Invalid method signature (method name missing): " + signature);
        }
        if (PATTERN_WILDCARD_ARGS.matcher(methodOrField.substring(p)).matches()) {
          // we create a method instance with the special descriptor string "**", which gets detected later:
          method = new Method(methodOrField.substring(0, p).trim(), WILDCARD_ARGS);
        } else {
          // we ignore the return type, it just allows the parser to succeed (so return type is void):
          try {
            method = Method.getMethod("void ".concat(methodOrField), true);
          } catch (IllegalArgumentException iae) {
            throw new ParseException("Invalid method signature: " + signature);
          }
        }
        field = null;
      } else {
        field = methodOrField;
        method = null;
      }
    } else {
      clazz = signature;
      method = null;
      field = null;
    }
    
    // check class & method/field signature, if it is really existent (in classpath), but we don't really load the class into JVM:
    if (AsmUtils.isGlob(clazz)) {
      if (method != null || field != null) {
        throw new ParseException(String.format(Locale.ENGLISH, "Class level glob pattern cannot be combined with methods/fields: %s", signature));
      }
      return Collections.singleton(clazz);
    } else {
      final ClassMetadata c;
      Collection<String> keys = new ArrayList<>();
      try {
        c = lookup.getClassFromClassLoader(clazz);
      } catch (ClassNotFoundException cnfe) {
        if (this.ignoreSignaturesOfMissingClasses || localIgnoreMissingClasses) {
          return null;
        }
        if (report.reportClassNotFound) {
          report.parseFailed(logger, String.format(Locale.ENGLISH, "Class '%s' not found on classpath", cnfe.getMessage()), signature);
        } else {
          missingClasses.add(clazz);
        }
        return null;
      }
      if (method != null) {
        assert field == null;
        // list all methods with this signature:
        boolean found = false;
        for (final Method m : c.methods) {
          if (m.getName().equals(method.getName()) && 
              (WILDCARD_ARGS.equals(method.getDescriptor()) || Arrays.equals(m.getArgumentTypes(), method.getArgumentTypes()))) {
            found = true;
            keys.add(getKey(c.className, m));
            // don't break when found, as there may be more covariant overrides!
          }
        }
        if (!found) {
          report.parseFailed(logger, "Method not found", signature);
          return null;
        }
      } else if (field != null) {
        assert method == null;
        if (!c.fields.contains(field)) {
          report.parseFailed(logger, "Field not found", signature);
          return null;
        }
        keys.add(getKey(c.className, field));
      } else {
        assert field == null && method == null;
        // only add the signature as class name
        keys.add(getKey(c.className));
      }
      return keys;
    }
}
  
  private void reportMissingSignatureClasses(Set<String> missingClasses) {
    if (missingClasses.isEmpty()) {
      return;
    }
    logger.warn("Some signatures were ignored because the following classes were not found on classpath:");
    logger.warn(AsmUtils.formatClassesAbbreviated(missingClasses));
  }

  private void addBundledSignatures(String name, String jdkTargetVersion, boolean logging, Set<String> missingClasses) throws IOException,ParseException {
    if (!name.matches("[A-Za-z0-9\\-\\.]+")) {
      throw new ParseException("Invalid bundled signature reference: " + name);
    }
    if (BS_JDK_NONPORTABLE.equals(name)) {
      if (logging) logger.info("Reading bundled API signatures: " + name);
      numberOfFiles++;
      forbidNonPortableRuntime = true;
      return;
    }
    name = fixTargetVersion(name);
    // use Checker.class hardcoded (not getClass) so we have a fixed package name:
    InputStream in = Checker.class.getResourceAsStream("signatures/" + name + ".txt");
    // automatically expand the compiler version in here (for jdk-* signatures without version):
    if (in == null && jdkTargetVersion != null && name.startsWith("jdk-") && !name.matches(".*?\\-\\d+(\\.\\d+)*")) {
      name = name + "-" + jdkTargetVersion;
      name = fixTargetVersion(name);
      in = Checker.class.getResourceAsStream("signatures/" + name + ".txt");
    }
    if (in == null) {
      throw new FileNotFoundException("Bundled signatures resource not found: " + name);
    }
    if (logging) logger.info("Reading bundled API signatures: " + name);
    parseSignaturesStream(in, true, missingClasses);
  }
  
  private void parseSignaturesStream(InputStream in, boolean isBundled, Set<String> missingClasses) throws IOException,ParseException {
    parseSignaturesFile(new InputStreamReader(in, StandardCharsets.UTF_8), isBundled, missingClasses);
  }

  private void parseSignaturesFile(Reader reader, boolean isBundled, Set<String> missingClasses) throws IOException,ParseException {
    numberOfFiles++;
    try (final BufferedReader r = new BufferedReader(reader)) {
      String line, defaultMessage = null;
      UnresolvableReporting reporter = failOnUnresolvableSignatures ? UnresolvableReporting.FAIL : UnresolvableReporting.WARNING;
      boolean localIgnoreMissingClasses = false;
      while ((line = r.readLine()) != null) {
        line = line.trim();
        if (line.length() == 0 || line.startsWith("#"))
          continue;
        if (line.startsWith("@")) {
          if (isBundled && line.startsWith(BUNDLED_PREFIX)) {
            final String name = line.substring(BUNDLED_PREFIX.length()).trim();
            addBundledSignatures(name, null, false, missingClasses);
          } else if (line.startsWith(DEFAULT_MESSAGE_PREFIX)) {
            defaultMessage = line.substring(DEFAULT_MESSAGE_PREFIX.length()).trim();
            if (defaultMessage.length() == 0) defaultMessage = null;
          } else if (line.equals(IGNORE_UNRESOLVABLE_LINE)) {
            if (isBundled) {
              reporter = UnresolvableReporting.SILENT;
            } else {
              logger.warn(String.format(Locale.ENGLISH, "'%s' inside signatures files is deprecated, prefer using '%s' to ignore signatures where the class is missing.",
                  IGNORE_UNRESOLVABLE_LINE, IGNORE_MISSING_CLASSES_LINE));
              reporter = UnresolvableReporting.WARNING;
            }
          } else if (line.equals(IGNORE_MISSING_CLASSES_LINE)) {
            localIgnoreMissingClasses = true;
          } else {
            throw new ParseException("Invalid line in signature file: " + line);
          }
        } else {
          addSignature(line, defaultMessage, reporter, localIgnoreMissingClasses, missingClasses);
        }
      }
    }
  }
  
  /** Reads a list of bundled API signatures from classpath. */
  public void addBundledSignatures(String name, String jdkTargetVersion) throws IOException,ParseException {
    final Set<String> missingClasses = new TreeSet<>();
    addBundledSignatures(name, jdkTargetVersion, true, missingClasses);
    reportMissingSignatureClasses(missingClasses);
  }
  
  /** Reads a list of API signatures. Closes the Reader when done (on Exception, too)! */
  public void parseSignaturesStream(InputStream in, String name) throws IOException,ParseException {
    logger.info("Reading API signatures: " + name);
    final Set<String> missingClasses = new TreeSet<>();
    parseSignaturesStream(in, false, missingClasses);
    reportMissingSignatureClasses(missingClasses);
  }
  
  /** Reads a list of API signatures from a String. */
  public void parseSignaturesString(String signatures) throws IOException,ParseException {
    logger.info("Reading inline API signatures...");
    final Set<String> missingClasses = new TreeSet<>();
    parseSignaturesFile(new StringReader(signatures), false, missingClasses);
    reportMissingSignatureClasses(missingClasses);
  }
  
  /** Returns if there are any signatures. */
  public boolean hasNoSignatures() {
    return 0 == signatures.size() + 
        classPatterns.size() +
        (forbidNonPortableRuntime ? 1 : 0);
  }
  
  /** Returns if no signatures files / inline signatures were parsed */
  public boolean noSignaturesFilesParsed() {
    return numberOfFiles == 0;
  }
  
  public void setSignaturesSeverity(Collection<String> signature, ViolationSeverity severity) throws ParseException, IOException {
    logger.info("Adjusting severity to " + severity + " for signatures...");
    for (String s : signature) {
      setSignatureSeverity(s, severity);
    }
  }
  
  public void setSignatureSeverity(String signature, ViolationSeverity severity) throws ParseException, IOException {
    Collection<String> keys = getKeys(UnresolvableReporting.SILENT, false, new HashSet<String>(), signature);
    if (keys != null) {
      for (String key : keys) {
        if (key.startsWith("c\000") || key.startsWith("f\000") || key.startsWith("m\000")) {
          severityPerSignature.put(key, severity);
        } else {
          severityPerClassPattern.put(AsmUtils.glob2Pattern(key), severity);
        }
      }
    }
  }
  
  /** Returns if bundled signature to enable heuristics for detection of non-portable runtime calls is used */
  public boolean isNonPortableRuntimeForbidden() {
    return this.forbidNonPortableRuntime;
  }
  
  private static String formatTypePrintout(String printout, String what) {
    return String.format(Locale.ENGLISH, "Forbidden %s use: %s", what, printout);
  }
  
  /**
   * Represents a violation (usage of a forbidden method/field/class).
   * Encapsulates both message and severity.
   */
  public static class ViolationResult {
      public final String message;
      public final ViolationSeverity severity;

      public ViolationResult(String message, ViolationSeverity severity) {
          this.message = message;
          this.severity = severity;
      }
  }

  public ViolationResult checkType(Type type, String what) {
    if (type.getSort() != Type.OBJECT) {
      return null; // we don't know this type, just pass!
    }
    final String key = getKey(type.getInternalName());
    final String printout = signatures.get(getKey(type.getInternalName()));
    if (printout != null) {
      return new ViolationResult(formatTypePrintout(printout, what), getSeverityForKey(key));
    }
    final String binaryClassName = type.getClassName();
    for (final ClassPatternRule r : classPatterns) {
      if (r.matches(binaryClassName)) {
        return new ViolationResult(formatTypePrintout(r.getPrintout(binaryClassName), what), getSeverityForClassName(binaryClassName));
      }
    }
    return null;
  }
  
  public ViolationResult checkMethod(String internalClassName, Method method) {
    final String key = getKey(internalClassName, method);
    final String printout = signatures.get(key);
    return (printout == null) ? null : new ViolationResult("Forbidden method invocation: ".concat(printout), getSeverityForKey(key));
  }
  
  public ViolationResult checkField(String internalClassName, String field) {
    final String key = getKey(internalClassName, field);
    final String printout = signatures.get(key);
    return (printout == null) ? null : new ViolationResult("Forbidden field access: ".concat(printout), getSeverityForKey(key));
  }

  private ViolationSeverity getSeverityForKey(String key) {
    return severityPerSignature.getOrDefault(key, failOnViolation ? ViolationSeverity.ERROR : ViolationSeverity.WARNING);
  }

  private ViolationSeverity getSeverityForClassName(String className) {
      for (final Map.Entry<Pattern, ViolationSeverity> e : severityPerClassPattern.entrySet()) {
          if (e.getKey().matcher(className).matches()) {
              return e.getValue();
          }
      }
      return failOnViolation ? ViolationSeverity.ERROR : ViolationSeverity.WARNING;
  }

  public static String fixTargetVersion(String name) throws ParseException {
    final Matcher m = JDK_SIG_PATTERN.matcher(name);
    if (m.matches()) {
      if (m.group(4) == null) {
        final String prefix = m.group(1);
        final int major = Integer.parseInt(m.group(2));
        final int minor = m.group(3) != null ? Integer.parseInt(m.group(3).substring(1)) : 0;
        if (major == 1 && minor >= 1 && minor < 9) {
          // Java 1.1 till 1.8 (aka 8):
          return prefix + "1." + minor;
        } else if (major > 1 && major < 9) {
          // fix pre-Java9 major version to use "1.x" syntax:
          if (minor == 0) {
            return prefix + "1." + major;
          }
        } else if (major >= 9 && minor > 0) {
          return prefix + major + "." + minor;
        } else  if (major >= 9 && minor == 0) {
          return prefix + major;
        }
      }
      throw new ParseException("Invalid bundled signature reference (JDK version is invalid): " + name);
    }
    return name;
  }
  
}
