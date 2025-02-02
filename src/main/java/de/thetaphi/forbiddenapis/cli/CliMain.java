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

package de.thetaphi.forbiddenapis.cli;

import static de.thetaphi.forbiddenapis.Checker.Option.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.net.JarURLConnection;
import java.net.URLConnection;
import java.net.URLClassLoader;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.MalformedURLException;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.codehaus.plexus.util.DirectoryScanner;

import de.thetaphi.forbiddenapis.AsmUtils;
import de.thetaphi.forbiddenapis.Checker;
import de.thetaphi.forbiddenapis.Constants;
import de.thetaphi.forbiddenapis.ForbiddenApiException;
import de.thetaphi.forbiddenapis.Logger;
import de.thetaphi.forbiddenapis.ParseException;
import de.thetaphi.forbiddenapis.StdIoLogger;

/**
 * CLI class with a static main() method
 */
public final class CliMain implements Constants {

  private final Logger logger;
  private final Option classpathOpt, dirOpt, includesOpt, excludesOpt, signaturesfileOpt, bundledsignaturesOpt, suppressannotationsOpt,
    allowmissingclassesOpt, ignoresignaturesofmissingclassesOpt, allowunresolvablesignaturesOpt, versionOpt, helpOpt, debugOpt;
  private final CommandLine cmd;
  
  public static final int EXIT_SUCCESS = 0;
  public static final int EXIT_VIOLATION = 1;
  public static final int EXIT_ERR_CMDLINE = 2;
  public static final int EXIT_UNSUPPORTED_JDK = 3;
  public static final int EXIT_ERR_OTHER = 4;

  public CliMain(String... args) throws ExitException {
    final OptionGroup required = new OptionGroup();
    required.setRequired(true);
    required.addOption(dirOpt = Option.builder("d")
        .desc("directory (or jar file) with class files to check for forbidden api usage; this directory is also added to classpath")
        .longOpt("dir")
        .hasArg()
        .argName("directory")
        .build());
    required.addOption(versionOpt = Option.builder("V")
        .desc("print product version and exit")
        .longOpt("version")
        .build());
    required.addOption(helpOpt = Option.builder("h")
        .desc("print this help")
        .longOpt("help")
        .build());
        
    final Options options = new Options();
    options.addOptionGroup(required);
    options.addOption(debugOpt = Option.builder()
        .desc("enable debug logging (stderr)")
        .longOpt("debug")
        .build());
    options.addOption(classpathOpt = Option.builder("c")
        .desc("class search path of directories and zip/jar files")
        .longOpt("classpath")
        .hasArgs()
        .valueSeparator(File.pathSeparatorChar)
        .argName("path")
        .build());
    options.addOption(includesOpt = Option.builder("i")
        .desc("ANT-style pattern to select class files (separated by commas or option can be given multiple times, defaults to '**/*.class')")
        .longOpt("includes")
        .hasArgs()
        .valueSeparator(',')
        .argName("pattern")
        .build());
    options.addOption(excludesOpt = Option.builder("e")
        .desc("ANT-style pattern to exclude some files from checks (separated by commas or option can be given multiple times)")
        .longOpt("excludes")
        .hasArgs()
        .valueSeparator(',')
        .argName("pattern")
        .build());
    options.addOption(signaturesfileOpt = Option.builder("f")
        .desc("path to a file containing signatures (option can be given multiple times)")
        .longOpt("signaturesfile")
        .hasArg()
        .argName("file")
        .build());
    options.addOption(bundledsignaturesOpt = Option.builder("b")
        .desc("name of a bundled signatures definition (separated by commas or option can be given multiple times)")
        .longOpt("bundledsignatures")
        .hasArgs()
        .valueSeparator(',')
        .argName("name")
        .build());
    options.addOption(suppressannotationsOpt = Option.builder()
        .desc("class name or glob pattern of annotation that suppresses error reporting in classes/methods/fields (separated by commas or option can be given multiple times)")
        .longOpt("suppressannotation")
        .hasArgs()
        .valueSeparator(',')
        .argName("classname")
        .build());
    options.addOption(allowmissingclassesOpt = Option.builder()
        .desc("don't fail if a referenced class is missing on classpath")
        .longOpt("allowmissingclasses")
        .build());
    options.addOption(ignoresignaturesofmissingclassesOpt = Option.builder()
        .desc("if a class is missing while parsing signatures files, all methods and fields from this class are silently ignored")
        .longOpt("ignoresignaturesofmissingclasses")
        .build());
    options.addOption(allowunresolvablesignaturesOpt = Option.builder()
        .desc("DEPRECATED: don't fail if a signature is not resolving")
        .longOpt("allowunresolvablesignatures")
        .build());

    try {
      this.cmd = new DefaultParser().parse(options, args);
      final boolean debugLogging = cmd.hasOption(debugOpt.getLongOpt());
      this.logger = debugLogging ? StdIoLogger.INSTANCE_DEBUG : StdIoLogger.INSTANCE;
      if (cmd.hasOption(helpOpt.getLongOpt())) {
        printHelp(options);
        throw new ExitException(EXIT_SUCCESS);
      }
      if (cmd.hasOption(versionOpt.getLongOpt())) {
        printVersion();
        throw new ExitException(EXIT_SUCCESS);
      }
    } catch (org.apache.commons.cli.ParseException pe) {
      printHelp(options);
      throw new ExitException(EXIT_ERR_CMDLINE);
    }
  }
  
  private void printVersion() {
    final Package pkg = this.getClass().getPackage();
    logger.info(String.format(Locale.ENGLISH,
      "%s %s",
      pkg.getImplementationTitle(), pkg.getImplementationVersion()
    ));
  }
  
  private void printHelp(Options options) {
    final HelpFormatter formatter = new HelpFormatter();
    String clazzName = getClass().getName();
    String cmdline = "java " + clazzName;
    try {
      final URLConnection conn = getClass().getClassLoader().getResource(AsmUtils.getClassResourceName(clazzName)).openConnection();
      if (conn instanceof JarURLConnection) {
        final URL jarUrl = ((JarURLConnection) conn).getJarFileURL();
        if ("file".equalsIgnoreCase(jarUrl.getProtocol())) {
          final String cwd = new File(".").getCanonicalPath(), path = new File(jarUrl.toURI()).getCanonicalPath();
          cmdline = "java -jar " + (path.startsWith(cwd) ? path.substring(cwd.length() + File.separator.length()) : path);
        }
      }
    } catch (IOException ioe) {
      // ignore, use default cmdline value
    } catch (URISyntaxException use) {
      // ignore, use default cmdline value
    }
    formatter.printHelp(cmdline + " [options]",
      "Scans a set of class files for forbidden API usage.",
      options,
      String.format(Locale.ENGLISH,
        "Exit codes: %d = SUCCESS, %d = forbidden API detected, %d = invalid command line, %d = unsupported JDK version, %d = other error (I/O,...)",
        EXIT_SUCCESS, EXIT_VIOLATION, EXIT_ERR_CMDLINE, EXIT_UNSUPPORTED_JDK, EXIT_ERR_OTHER
      )
    );
  }
  
  public void run() throws ExitException {
    File firstClassesDirectory = new File(cmd.getOptionValue(dirOpt.getLongOpt())).getAbsoluteFile();

    if (!firstClassesDirectory.exists()) {
      throw new ExitException(EXIT_ERR_OTHER, "Directory with class files does not exist: " + firstClassesDirectory);
    }

    try {
      if (!firstClassesDirectory.isDirectory() && firstClassesDirectory.getName().endsWith(".jar")) {
        // Create a temporary directory
        Path tempDir = Files.createTempDirectory("jar_extract_");
        tempDir.toFile().deleteOnExit();
        System.out.println("Directory is a jar - temporary extracting to " + tempDir);

        // Extract JAR contents
        try (JarFile jarFile = new JarFile(firstClassesDirectory)) {
          Enumeration<JarEntry> entries = jarFile.entries();
          while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            Path entryDestination = tempDir.resolve(entry.getName());

            if (entry.isDirectory()) {
              Files.createDirectories(entryDestination);
            } else {
              Files.createDirectories(entryDestination.getParent());
              try (InputStream in = jarFile.getInputStream(entry);
                   OutputStream out = Files.newOutputStream(entryDestination)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = in.read(buffer)) > 0) {
                  out.write(buffer, 0, len);
                }
              }
            }
            entryDestination.toFile().deleteOnExit();
          }
        }
        firstClassesDirectory = tempDir.toFile();
      }
    } catch (IOException e) {
      throw new ExitException(EXIT_ERR_OTHER, "Could not unpack jar file: " + e);
    }

    final File classesDirectory = firstClassesDirectory;

    // parse classpath given as argument; add -d to classpath, too
    final String[] classpath = cmd.getOptionValues(classpathOpt.getLongOpt());
    final URL[] urls;
    try {
      if (classpath == null) {
        urls = new URL[] { classesDirectory.toURI().toURL() };
      } else {
        urls = new URL[classpath.length + 1];
        int i = 0;
        for (final String cpElement : classpath) {
          urls[i++] = new File(cpElement).toURI().toURL();
        }
        urls[i++] = classesDirectory.toURI().toURL();
        assert i == urls.length;
      }
    } catch (MalformedURLException mfue) {
      throw new ExitException(EXIT_ERR_OTHER, "The given classpath is invalid: " + mfue);
    }
    logger.debug("Classpath: " + Arrays.toString(urls));

    try (final URLClassLoader loader = URLClassLoader.newInstance(urls, ClassLoader.getSystemClassLoader())) {
      final EnumSet<Checker.Option> options = EnumSet.of(FAIL_ON_VIOLATION);
      if (!cmd.hasOption(allowmissingclassesOpt.getLongOpt())) options.add(FAIL_ON_MISSING_CLASSES);
      if (cmd.hasOption(allowunresolvablesignaturesOpt.getLongOpt())) {
        logger.warn(DEPRECATED_WARN_FAIL_ON_UNRESOLVABLE_SIGNATURES);
      } else {
        options.add(FAIL_ON_UNRESOLVABLE_SIGNATURES);
      }
      if (cmd.hasOption(ignoresignaturesofmissingclassesOpt.getLongOpt())) {
        options.add(IGNORE_SIGNATURES_OF_MISSING_CLASSES);
      }
      final Checker checker = new Checker(logger, loader, options);
      
      if (!checker.isSupportedJDK) {
        throw new ExitException(EXIT_UNSUPPORTED_JDK, String.format(Locale.ENGLISH, 
          "Your Java runtime (%s %s) is not supported by forbiddenapis. Please run the checks with a supported JDK!",
          System.getProperty("java.runtime.name"), System.getProperty("java.runtime.version")));
      }
      
      final String[] suppressAnnotations = cmd.getOptionValues(suppressannotationsOpt.getLongOpt());
      if (suppressAnnotations != null) for (String a : suppressAnnotations) {
        checker.addSuppressAnnotation(a);
      }
      
      logger.info("Scanning for classes to check...");

      String[] includes = cmd.getOptionValues(includesOpt.getLongOpt());
      if (includes == null || includes.length == 0) {
        includes = new String[] { "**/*.class" };
      }
      final String[] excludes = cmd.getOptionValues(excludesOpt.getLongOpt());
      final DirectoryScanner ds = new DirectoryScanner();
      ds.setBasedir(classesDirectory);
      ds.setCaseSensitive(true);
      ds.setIncludes(includes);
      ds.setExcludes(excludes);
      ds.addDefaultExcludes();
      ds.scan();
      final String[] files = ds.getIncludedFiles();
      if (files.length == 0) {
        throw new ExitException(EXIT_ERR_OTHER, String.format(Locale.ENGLISH,
          "No classes found in directory %s (includes=%s, excludes=%s).",
          classesDirectory, Arrays.toString(includes), Arrays.toString(excludes)));
      }
      
      try {
        final String[] bundledSignatures = cmd.getOptionValues(bundledsignaturesOpt.getLongOpt());
        if (bundledSignatures != null) for (String bs : new LinkedHashSet<>(Arrays.asList(bundledSignatures))) {
          checker.addBundledSignatures(bs, null);
        }
        
        final String[] signaturesFiles = cmd.getOptionValues(signaturesfileOpt.getLongOpt());
        if (signaturesFiles != null) for (String sf : new LinkedHashSet<>(Arrays.asList(signaturesFiles))) {
          final File f = new File(sf).getAbsoluteFile();
          checker.parseSignaturesFile(f);
        }
      } catch (IOException ioe) {
        throw new ExitException(EXIT_ERR_OTHER, "IO problem while reading files with API signatures: " + ioe);
      } catch (ParseException pe) {
        throw new ExitException(EXIT_ERR_OTHER, "Parsing signatures failed: " + pe.getMessage());
      }

      if (checker.hasNoSignatures()) {
        if (checker.noSignaturesFilesParsed()) {
          throw new ExitException(EXIT_ERR_CMDLINE, String.format(Locale.ENGLISH,
            "No API signatures given as parameters; use '--%s' and/or '--%s' to specify those!",
            bundledsignaturesOpt.getLongOpt(), signaturesfileOpt.getLongOpt()
          ));
      } else {
          logger.info("Skipping execution because no API signatures are available.");
          return;
        }
      }

      try {
        checker.addClassesToCheck(classesDirectory, files);
      } catch (IOException ioe) {
        throw new ExitException(EXIT_ERR_OTHER, "Failed to load one of the given class files: " + ioe);
      }

      try {
        checker.run();
      } catch (ForbiddenApiException fae) {
        throw new ExitException(EXIT_VIOLATION, fae.getMessage());
      }
    } catch (IOException ioe) {
      throw new ExitException(EXIT_ERR_OTHER, "General IO problem: " + ioe);
    }
  }
  
  public static void main(String... args) {
    try {
      new CliMain(args).run();
    } catch (ExitException e) {
      if (e.getMessage() != null) {
        StdIoLogger.INSTANCE.error(e.getMessage());
      }
      if (e.exitCode != 0) {
        System.exit(e.exitCode);
      }
    }
  }
  
}