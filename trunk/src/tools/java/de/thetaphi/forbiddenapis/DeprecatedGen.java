package de.thetaphi.forbiddenapis;

/*
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

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.io.IOException;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class DeprecatedGen implements Opcodes {
  
  final static int ACC_PUBLICDEPRECATED = ACC_PUBLIC | ACC_DEPRECATED;
  
  final static String NL = System.getProperty("line.separator", "\n");
  final static String LICENSE_HEADER = new StringBuilder()
    .append("# This file contains API signatures extracted from the rt.jar file").append(NL)
    .append("# shipped with the class library of Oracle's Java Runtime Environment.").append(NL)
    .append("# It is provided here for reference, but can easily regenerated by executing:").append(NL)
    .append("# $ java ").append(DeprecatedGen.class.getName()).append(" /path/to/rt.jar /path/to/this/file.txt").append(NL)
    .append(NL)
    .append("# This file contains all public, deprecated API signatures extracted from Java version ").append(System.getProperty("java.version")).append('.').append(NL)
    .append(NL)
    .toString();
  
  final SortedSet<String> deprecated = new TreeSet<String>();
  
  protected boolean isInternalClass(String className) {
    return className.startsWith("sun.") || className.startsWith("com.sun.");
  }

  void checkClass(final ClassReader reader) {
    final String className =  Type.getObjectType(reader.getClassName()).getClassName();
    // exclude internal classes like Unsafe,... and non-public classes!
    // Note: reader.getAccess() does no indicate if class is deprecated, as this is a special
    // attribute or annotation (both is handled later), we have to parse the class - this is just early exit!
    if ((reader.getAccess() & ACC_PUBLIC) == 0 || isInternalClass(className)) {
      return;
    }
    reader.accept(new ClassVisitor(ASM4) {
      boolean classDeprecated = false;
    
      @Override
      public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        if ((access & ACC_PUBLICDEPRECATED) == ACC_PUBLICDEPRECATED) {
          deprecated.add(className);
          classDeprecated = true;
        }
      }

      @Override
      public MethodVisitor visitMethod(final int access, final String name, final String desc, final String signature, final String[] exceptions) {
        if (!classDeprecated && (access & ACC_PUBLICDEPRECATED) == ACC_PUBLICDEPRECATED) {
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
        if (!classDeprecated && (access & ACC_PUBLICDEPRECATED) == ACC_PUBLICDEPRECATED) {
          deprecated.add(className + '#' + name);
        }
        return null;
      }
    }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
  }
  
  void parseRT(InputStream in) throws IOException  {
    final ZipInputStream zip = new ZipInputStream(in);
    ZipEntry entry;
    while ((entry = zip.getNextEntry()) != null) {
      try {
        if (entry.isDirectory()) continue;
        if (entry.getName().endsWith(".class")) {
          final ClassReader classReader;
          try {
            classReader = new ClassReader(zip);
          } catch (IllegalArgumentException iae) {
            // unfortunately the ASM IAE has no message, so add good info!
            throw new IllegalArgumentException("The class file format of your rt.jar seems to be too recent to be parsed by ASM (may need to be upgraded).");
          }
          checkClass(classReader);
        }
      } finally {
        zip.closeEntry();
      }
    }
  }
  
  void writeOutput(OutputStream out) throws IOException {
    BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, "UTF-8"));
    writer.write(LICENSE_HEADER);
    for (final String s : deprecated) {
      writer.write(s);
      writer.newLine();
    }
    writer.flush();
  }

  public static void main(String... args) throws Exception {
    if (args.length != 2) {
      System.err.println("Invalid parameters; must be path to rt.jar and output file");
      System.exit(1);
    }
    System.err.println("Reading '" + args[0] + "' and extracting deprecated APIs to signature file '" + args[1]+ "'...");
    final InputStream in = new FileInputStream(args[0]);
    try { 
      final DeprecatedGen parser = new DeprecatedGen();
      parser.parseRT(in);
      final FileOutputStream out = new FileOutputStream(args[1]);
      try {
        parser.writeOutput(out);
      } finally {
        out.close();
      }
      System.err.println("Deprecated API sigatures for Java version " + System.getProperty("java.version") + " written successfully.");
    } finally {
      in.close();
    }
  }
}
