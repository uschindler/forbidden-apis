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

package de.thetaphi.forbiddenapis;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.Locale;
import java.util.SortedSet;
import java.util.TreeSet;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Lists all classes in Java runtime, scans them for deprecated signatures and writes them to a signatures file. */
public abstract class DeprecatedGen<Input> implements Opcodes {
  
  final static String NL = System.getProperty("line.separator", "\n");
  final SortedSet<String> deprecated = new TreeSet<>();
  final String javaVersion, header;
  
  private final Input source;
  private final File output;
  
  public DeprecatedGen(String javaVersion, Input source, File output) {
    this.javaVersion = javaVersion;
    this.source = source;
    this.output = output;
    this.header = new StringBuilder()
      .append("# This file contains API signatures extracted from the rt.jar / jimage file shipped with the class library of Oracle's Java Runtime Environment.").append(NL)
      .append("# It is provided here for reference, but can easily regenerated by executing from the source folder of forbidden-apis:").append(NL)
      .append("# $ ant generate-deprecated").append(NL)
      .append(NL)
      .append("# This file contains all public, deprecated API signatures in Java version ").append(javaVersion)
        .append(" (extracted from build ").append(System.getProperty("java.version")).append(").").append(NL)
      .append(NL)
      .append("@ignoreUnresolvable").append(NL)
      .append("@defaultMessage Deprecated in Java ").append(javaVersion).append(NL)
      .append(NL)
      .toString();
  }
  
  protected boolean isDeprecated(int access) {
   return ((access & (ACC_PUBLIC | ACC_PROTECTED)) != 0 && (access & ACC_DEPRECATED) != 0);
  }
  
  protected void parseClass(InputStream in) throws IOException {
    final ClassReader reader;
    try {
      reader = AsmUtils.readAndPatchClass(in);
    } catch (IllegalArgumentException iae) {
      // unfortunately the ASM IAE has no message, so add good info!
      throw new IllegalArgumentException("The class file format of your runtime seems to be too recent to be parsed by ASM (may need to be upgraded).");
    }
    final String className =  Type.getObjectType(reader.getClassName()).getClassName();
    // exclude internal classes like Unsafe,... and non-public classes!
    // Note: reader.getAccess() does no indicate if class is deprecated, as this is a special
    // attribute or annotation (both is handled later), we have to parse the class - this is just early exit!
    if ((reader.getAccess() & ACC_PUBLIC) == 0 || !AsmUtils.isPortableRuntimeClass(className)) {
      return;
    }
    reader.accept(new ClassVisitor(ASM8) {
      boolean classDeprecated = false;
    
      @Override
      public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        if (isDeprecated(access)) {
          deprecated.add(className);
          classDeprecated = true;
        }
      }

      @Override
      public MethodVisitor visitMethod(final int access, final String name, final String desc, final String signature, final String[] exceptions) {
        if (!classDeprecated && isDeprecated(access)) {
          final Type[] args = Type.getType(desc).getArgumentTypes();
          final StringBuilder sb = new StringBuilder(className).append('#').append(name).append('(');
          boolean comma = false;
          for (final Type t : args) {
            if (comma) sb.append(',');
            sb.append(t.getClassName());
            comma = true;
          }
          sb.append(')');
          deprecated.add(sb.toString());
        }
        return null;
      }
        
      @Override
      public FieldVisitor visitField(final int access, final String name, final String desc, final String signature, final Object value) {
        if (!classDeprecated && isDeprecated(access)) {
          deprecated.add(className + '#' + name);
        }
        return null;
      }
    }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
  }
  
  protected void writeOutput(OutputStream out) throws IOException {
    BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, "UTF-8"));
    writer.write(header);
    for (final String s : deprecated) {
      writer.write(s);
      writer.newLine();
    }
    writer.flush();
  }
  
  protected abstract void collectClasses(Input source) throws IOException;
  
  @SuppressForbidden
  public void run() throws IOException {
    System.err.println(String.format(Locale.ENGLISH, "Reading '%s' and extracting deprecated APIs to signatures file '%s'...", source, output));
    collectClasses(source);
    try (final FileOutputStream out = new FileOutputStream(output)) {
      writeOutput(out);
    }
    System.err.println("Deprecated API signatures for Java version " + javaVersion + " written successfully.");
  }

}
