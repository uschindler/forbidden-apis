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

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.RecordComponentVisitor;
import org.objectweb.asm.Type;
import org.objectweb.asm.TypePath;
import org.objectweb.asm.commons.Method;

import de.thetaphi.forbiddenapis.Checker.ViolationSeverity;
import de.thetaphi.forbiddenapis.Signatures.ViolationResult;

public final class ClassScanner extends ClassVisitor implements Constants {
  private final boolean forbidNonPortableRuntime;
  final ClassMetadata metadata;
  final RelatedClassLookup lookup;
  final List<ForbiddenViolation> violations = new ArrayList<>();
  
  final Signatures forbiddenSignatures;
  
  // pattern that matches binary (dotted) class name of all annotations that suppress:
  final Pattern suppressAnnotations;
  
  private String source = null;
  private boolean isDeprecated = false;
  private boolean done = false;
  int currentGroupId = 0;
  
  // Mapping from a (possible) lambda Method to groupId of declaring method
  final Map<Method,Integer> lambdas = new HashMap<>();
  
  // all groups that were disabled due to suppressing annotation
  final BitSet suppressedGroups = new BitSet();
  boolean classSuppressed = false;
  private final boolean failOnViolation;
  
  public ClassScanner(ClassMetadata metadata, RelatedClassLookup lookup, Signatures forbiddenSignatures, final Pattern suppressAnnotations, boolean failOnViolation) {
    super(Opcodes.ASM9);
    this.metadata = metadata;
    this.lookup = lookup;
    this.forbiddenSignatures = forbiddenSignatures;
    this.suppressAnnotations = suppressAnnotations;
    this.forbidNonPortableRuntime = forbiddenSignatures.isNonPortableRuntimeForbidden();
    this.failOnViolation = failOnViolation;
  }
  
  private void checkDone() {
    if (done) return;
    throw new IllegalStateException("Class not fully scanned.");
  }
  
  public List<ForbiddenViolation> getSortedViolations() {
    checkDone();
    return classSuppressed ? Collections.<ForbiddenViolation>emptyList() : Collections.unmodifiableList(violations);
  }
  
  public String getSourceFile() {
    return source;
  }
  
  ViolationResult checkClassUse(Type type, String what, boolean isAnnotation, String origInternalName) {
    while (type.getSort() == Type.ARRAY) {
      type = type.getElementType(); // unwrap array
    }
    if (type.getSort() != Type.OBJECT) {
      return null; // we don't know this type, just pass!
    }
    final ViolationResult violation = forbiddenSignatures.checkType(type, what);
    if (violation != null) {
      return violation;
    }
    // try best to check for non portable runtime
    if (forbidNonPortableRuntime) try {
      final String binaryClassName = type.getClassName();
      final ClassMetadata c = lookup.lookupRelatedClass(type.getInternalName(), origInternalName);
      if (c != null && c.isNonPortableRuntime) {
        return new ViolationResult(String.format(Locale.ENGLISH,
          "Forbidden %s use: %s [non-portable or internal runtime class]",
          what, binaryClassName), failOnViolation ? ViolationSeverity.ERROR : ViolationSeverity.WARNING);
      }
    } catch (RelatedClassLoadingException e) {
      // only throw exception if it is not an annotation
      if (false == isAnnotation) throw e;
    }
    return null;
  }
  
  ViolationResult checkClassUse(String internalName, String what, String origInternalName) {
    return checkClassUse(Type.getObjectType(internalName), what, false, origInternalName);
  }
  
  // TODO: @FunctionalInterface from Java 8 on
  static interface AncestorVisitor {
    final ViolationResult STOP = new ViolationResult("STOP", null);
    
    ViolationResult visit(ClassMetadata c, String origName, boolean isInterfaceOfAncestor, boolean previousInRuntime);
  }
  
  ViolationResult visitAncestors(ClassMetadata cls, AncestorVisitor visitor, boolean visitSelf, boolean visitInterfacesFirst) {
    if (visitSelf) {
      final ViolationResult result = visitor.visit(cls, cls.className, cls.isInterface, cls.isRuntimeClass);
      if (result == AncestorVisitor.STOP) {
        return null;
      }
      if (result != null) {
        return result;
      }
    }
    return visitAncestorsRecursive(cls, cls.className, visitor, cls.isRuntimeClass, visitInterfacesFirst);
  }
  
  private ViolationResult visitSuperclassRecursive(ClassMetadata cls, String origName, AncestorVisitor visitor, boolean previousInRuntime, boolean visitInterfacesFirst) {
    if (cls.superName != null) {
      final ClassMetadata c = lookup.lookupRelatedClass(cls.superName, origName);
      if (c != null) {
        ViolationResult result = visitor.visit(c, origName, false, previousInRuntime);
        if (result != AncestorVisitor.STOP) {
          if (result != null) {
            return result;
          }
          result = visitAncestorsRecursive(c, origName, visitor, cls.isRuntimeClass, visitInterfacesFirst);
          if (result != null) {
            return result;
          }
        }
      }
    }
    return null;
  }
  
  private ViolationResult visitInterfacesRecursive(ClassMetadata cls, String origName, AncestorVisitor visitor, boolean previousInRuntime, boolean visitInterfacesFirst) {
    if (cls.interfaces != null) {
      for (String intf : cls.interfaces) {
        final ClassMetadata c = lookup.lookupRelatedClass(intf, origName);
        if (c == null) continue;
        ViolationResult result = visitor.visit(c, origName, true, previousInRuntime);
        if (result != AncestorVisitor.STOP) {
          if (result != null) {
            return result;
          }
          result = visitAncestorsRecursive(c, origName, visitor, cls.isRuntimeClass, visitInterfacesFirst);
          if (result != null) {
            return result;
          }
        }
      }
    }
    return null;
  }
  
  private ViolationResult visitAncestorsRecursive(ClassMetadata cls, String origName, AncestorVisitor visitor, boolean previousInRuntime, boolean visitInterfacesFirst) {
    ViolationResult result;
    if (visitInterfacesFirst) {
      result = visitInterfacesRecursive(cls, origName, visitor, previousInRuntime, visitInterfacesFirst);
      if (result != null) {
        return result;
      }
    }
    result = visitSuperclassRecursive(cls, origName, visitor, previousInRuntime, visitInterfacesFirst);
    if (result != null) {
      return result;
    }
    if (!visitInterfacesFirst) {
      result = visitInterfacesRecursive(cls, origName, visitor, previousInRuntime, visitInterfacesFirst);
      if (result != null) {
        return result;
      }
    }
    return null;
  }
  
  // TODO: convert to lambda method with method reference
  private final AncestorVisitor classRelationAncestorVisitor = new AncestorVisitor() {
    @Override
    public ViolationResult visit(ClassMetadata c, String origName, boolean isInterfaceOfAncestor, boolean previousInRuntime) {
      if (previousInRuntime && c.isNonPortableRuntime) {
        return null; // something inside the JVM is extending internal class/interface
      }
      return checkClassUse(c.className, isInterfaceOfAncestor ? "interface" : "class", origName);
    }
  };
  
  ViolationResult checkType(Type type) {
    while (type != null) {
      ViolationResult violation;
      switch (type.getSort()) {
        case Type.OBJECT:
          final String internalName = type.getInternalName();
          violation = checkClassUse(type, "class/interface", false, internalName);
          if (violation != null) {
            return violation;
          }
          final ClassMetadata c = lookup.lookupRelatedClass(internalName, internalName);
          return (c == null) ? null : visitAncestors(c, classRelationAncestorVisitor, false, false);
        case Type.ARRAY:
          type = type.getElementType();
          break;
        case Type.METHOD:
          final ArrayList<ViolationResult> violations = new ArrayList<>();
          violation = checkType(type.getReturnType());
          if (violation != null) {
            violations.add(violation);
          }
          for (final Type t : type.getArgumentTypes()) {
            violation = checkType(t);
            if (violation != null) {
              violations.add(violation);
            }
          }
          if (violations.isEmpty()) {
            return null;
          } else if (violations.size() == 1) {
            return violations.get(0);
          } else {
            final StringBuilder sb = new StringBuilder();
            boolean nl = false;
            ViolationSeverity severity = null;
            for (final ViolationResult v : violations) {
              if (nl) sb.append(ForbiddenViolation.SEPARATOR);
              sb.append(v.message);
              nl = true;
              // use the highest severity reported on this method
              if (severity == null || v.severity.ordinal() > severity.ordinal()) {
                  severity = v.severity;
              }
            }
            return new ViolationResult(sb.toString(), severity);
          }
        default:
          return null;
      }
    }
    return null;
  }
  
  ViolationResult checkDescriptor(String desc) {
    return checkType(Type.getType(desc));
  }
  
  ViolationResult checkAnnotationDescriptor(Type type, boolean visible) {
    // for annotations, we don't need to look into super-classes, interfaces,...
    return checkClassUse(type, "annotation", true, type.getInternalName());
  }
  
  void maybeSuppressCurrentGroup(Type annotation) {
    if (suppressAnnotations.matcher(annotation.getClassName()).matches()) {
      suppressedGroups.set(currentGroupId);
    }
  }
  
  private void reportClassViolation(ViolationResult violation, String where) {
    if (violation != null) {
      violations.add(new ForbiddenViolation(currentGroupId, violation.message, where, -1, violation.severity));
    }
  }
  
  @Override
  public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
    if (!Objects.equals(name, metadata.className)) {
      throw new AssertionError("Wrong class parsed: " + name);
    }
    this.isDeprecated = (access & Opcodes.ACC_DEPRECATED) != 0;
    reportClassViolation(visitAncestors(metadata, classRelationAncestorVisitor, false, false), "class declaration");
    if (this.isDeprecated) {
      classSuppressed |= suppressAnnotations.matcher(DEPRECATED_TYPE.getClassName()).matches();
      reportClassViolation(checkType(DEPRECATED_TYPE), "deprecation on class declaration");
    }
  }
  
  @Override
  public void visitSource(String source, String debug) {
    this.source = source;
  }
  
  @Override
  public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
    if (this.isDeprecated && DEPRECATED_DESCRIPTOR.equals(desc)) {
      // don't report 2 times!
      return null;
    }
    final Type type = Type.getType(desc);
    classSuppressed |= suppressAnnotations.matcher(type.getClassName()).matches();
    reportClassViolation(checkAnnotationDescriptor(type, visible), "annotation on class declaration");
    return null;
  }
  
  @Override
  public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath, String desc, boolean visible) {
    reportClassViolation(checkAnnotationDescriptor(Type.getType(desc), visible), "type annotation on class declaration");
    return null;
  }
  
  @Override
  public FieldVisitor visitField(final int access, final String name, final String desc, String signature, Object value) {
    currentGroupId++;
    if (classSuppressed) {
      return null;
    }
    return new FieldVisitor(Opcodes.ASM9) {
      final boolean isDeprecated = (access & Opcodes.ACC_DEPRECATED) != 0;
      {
        // only check signature, if field is not synthetic
        if ((access & Opcodes.ACC_SYNTHETIC) == 0) {
          reportFieldViolation(checkDescriptor(desc), "field declaration");
        }
        if (this.isDeprecated) {
          maybeSuppressCurrentGroup(DEPRECATED_TYPE);
          reportFieldViolation(checkType(DEPRECATED_TYPE), "deprecation on field declaration");
        }
      }
      
      @Override
      public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
        if (this.isDeprecated && DEPRECATED_DESCRIPTOR.equals(desc)) {
          // don't report 2 times!
          return null;
        }
        final Type type = Type.getType(desc);
        maybeSuppressCurrentGroup(type);
        reportFieldViolation(checkAnnotationDescriptor(type, visible), "annotation on field declaration");
        return null;
      }

      @Override
      public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath, String desc, boolean visible) {
        reportFieldViolation(checkAnnotationDescriptor(Type.getType(desc), visible), "type annotation on field declaration");
        return null;
      }
      
      private void reportFieldViolation(ViolationResult violationResult, String where) {
        if (violationResult != null) {
          violations.add(new ForbiddenViolation(currentGroupId, violationResult.message, String.format(Locale.ENGLISH, "%s of '%s'", where, name), -1, violationResult.severity));
        }
      }
    };
  }
  
  @Override
  public MethodVisitor visitMethod(final int access, final String name, final String desc, String signature, String[] exceptions) {
    currentGroupId++;
    if (classSuppressed) {
      return null;
    }
    return new MethodVisitor(Opcodes.ASM9) {
      private final Method myself = new Method(name, desc);
      private final boolean isDeprecated = (access & Opcodes.ACC_DEPRECATED) != 0;
      private int lineNo = -1;
      
      {
        // only check signature, if method is not synthetic
        if ((access & Opcodes.ACC_SYNTHETIC) == 0) {
          reportMethodViolation(checkDescriptor(desc), "method declaration");
        }
        if (this.isDeprecated) {
          maybeSuppressCurrentGroup(DEPRECATED_TYPE);
          reportMethodViolation(checkType(DEPRECATED_TYPE), "deprecation on method declaration");
        }
      }
            
      private ViolationResult checkMethodAccess(String owner, final Method method, final boolean callIsVirtual) {
        if  (CLASS_CONSTRUCTOR_METHOD_NAME.equals(method.getName())) {
          // we don't check for violations on class constructors
          return null;
        }
        ViolationResult violation = checkClassUse(owner, "class/interface", owner);
        if (violation != null) {
          return violation;
        }
        // do a quick check that works without a ClassSignature (a more thorough check is done later):
        violation = forbiddenSignatures.checkMethod(owner, method);
        if (violation != null) {
          return violation;
        }
        if (CONSTRUCTOR_METHOD_NAME.equals(method.getName())) {
          return null; // don't look into superclasses or interfaces to find constructors!
        }
        final ClassMetadata c = lookup.lookupRelatedClass(owner, owner);
        if (c == null) {
          return null;
        }
        return visitAncestors(c, new AncestorVisitor() {
          @Override
          public ViolationResult visit(ClassMetadata c, String origName, boolean isInterfaceOfAncestor, boolean previousInRuntime) {
            final Method lookupMethod;
            if (c.signaturePolymorphicMethods.contains(method.getName())) {
              // convert the invoked descriptor to a signature polymorphic one for the lookup
              lookupMethod = new Method(method.getName(), SIGNATURE_POLYMORPHIC_DESCRIPTOR);
            } else {
              lookupMethod = method;
            }
            if (!c.methods.contains(lookupMethod)) {
              return null;
            }
            // is we have a virtual call, look into superclasses, otherwise stop:
            final ViolationResult notFoundRet = callIsVirtual ? null : AncestorVisitor.STOP;
            if (previousInRuntime && c.isNonPortableRuntime) {
              return notFoundRet; // something inside the JVM is extending internal class/interface
            }
            ViolationResult violation = forbiddenSignatures.checkMethod(c.className, lookupMethod);
            if (violation != null) {
              return violation;
            }
            // for interfaces we don't check the class use (it is too strict, if just the interface is implemented, but nothing more!):
            if (!isInterfaceOfAncestor) {
              violation = checkClassUse(c.className, "class", origName);
              if (violation != null) {
                return violation;
              }
            }
            return notFoundRet;
          }
        }, true, false /* JVM spec says: interfaces after superclasses */);
      }

      private ViolationResult checkFieldAccess(String owner, final String field) {
        ViolationResult violation = checkClassUse(owner, "class/interface", owner);
        if (violation != null) {
          return violation;
        }
        // do a quick check that works without a ClassSignature (a more thorough check is done later):
        violation = forbiddenSignatures.checkField(owner, field);
        if (violation != null) {
          return violation;
        }
        final ClassMetadata c = lookup.lookupRelatedClass(owner, owner);
        if (c == null) {
          return null;
        }
        return visitAncestors(c, new AncestorVisitor() {
          @Override
          public ViolationResult visit(ClassMetadata c, String origName, boolean isInterfaceOfAncestor, boolean previousInRuntime) {
            if (!c.fields.contains(field)) {
              return null;
            }
            // we found the field: from now on we use STOP to exit, because fields are not virtual!
            if (previousInRuntime && c.isNonPortableRuntime) {
              return STOP; // something inside the JVM is extending internal class/interface
            }
            ViolationResult violation = forbiddenSignatures.checkField(c.className, field);
            if (violation != null) {
              return violation;
            }
            // for interfaces we don't check the class use (it is too strict, if just the interface is implemented, but nothing more!):
            if (!isInterfaceOfAncestor) {
              violation = checkClassUse(c.className, "class", origName);
              if (violation != null) {
                return violation;
              }
            }
            // we found the field and as those are not virtual, there is no need to go up in class hierarchy:
            return STOP;
          }
        }, true, true /* JVM spec says: superclasses after interfaces */);
      }
      
      private ViolationResult checkHandle(Handle handle, boolean checkLambdaHandle) {
        switch (handle.getTag()) {
          case Opcodes.H_GETFIELD:
          case Opcodes.H_PUTFIELD:
          case Opcodes.H_GETSTATIC:
          case Opcodes.H_PUTSTATIC:
            return checkFieldAccess(handle.getOwner(), handle.getName());
          case Opcodes.H_INVOKEVIRTUAL:
          case Opcodes.H_INVOKESTATIC:
          case Opcodes.H_INVOKESPECIAL:
          case Opcodes.H_NEWINVOKESPECIAL:
          case Opcodes.H_INVOKEINTERFACE:
            final Method m = new Method(handle.getName(), handle.getDesc());
            if (checkLambdaHandle && handle.getOwner().equals(metadata.className) && handle.getName().startsWith(LAMBDA_METHOD_NAME_PREFIX)) {
              // as described in <http://cr.openjdk.java.net/~briangoetz/lambda/lambda-translation.html>,
              // we will record this metafactory call as "lambda" invokedynamic,
              // so we can assign the called lambda with the same groupId like *this* method:
              lambdas.put(m, currentGroupId);
            }
            final boolean callIsVirtual = (handle.getTag() == Opcodes.H_INVOKEVIRTUAL) || (handle.getTag() == Opcodes.H_INVOKEINTERFACE);
            return checkMethodAccess(handle.getOwner(), m, callIsVirtual);
        }
        return null;
      }
      
      private ViolationResult checkConstant(Object cst, boolean checkLambdaHandle) {
        if (cst instanceof Type) {
          return checkType((Type) cst);
        } else if (cst instanceof Handle) {
          return checkHandle((Handle) cst, checkLambdaHandle);
        }
        return null;
      }

      @Override
      public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
        if (this.isDeprecated && DEPRECATED_DESCRIPTOR.equals(desc)) {
          // don't report 2 times!
          return null;
        }
        final Type type = Type.getType(desc);
        maybeSuppressCurrentGroup(type);
        reportMethodViolation(checkAnnotationDescriptor(type, visible), "annotation on method declaration");
        return null;
      }

      @Override
      public AnnotationVisitor visitParameterAnnotation(int parameter, String desc, boolean visible) {
        reportMethodViolation(checkAnnotationDescriptor(Type.getType(desc), visible), "parameter annotation on method declaration");
        return null;
      }

      @Override
      public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath, String desc, boolean visible) {
        reportMethodViolation(checkAnnotationDescriptor(Type.getType(desc), visible), "type annotation on method declaration");
        return null;
      }

      @Override
      public AnnotationVisitor visitInsnAnnotation(int typeRef, TypePath typePath, String desc, boolean visible) {
        reportMethodViolation(checkAnnotationDescriptor(Type.getType(desc), visible), "annotation in method body");
        return null;
      }

      @Override
      public AnnotationVisitor visitLocalVariableAnnotation(int typeRef, TypePath typePath, Label[] start, Label[] end, int[] index, String desc, boolean visible) {
        reportMethodViolation(checkAnnotationDescriptor(Type.getType(desc), visible), "annotation in method body");
        return null;
      }
      
      @Override
      public AnnotationVisitor visitTryCatchAnnotation(int typeRef, TypePath typePath, String desc, boolean visible) {
        reportMethodViolation(checkAnnotationDescriptor(Type.getType(desc), visible), "annotation in method body");
        return null;
      }
      
      @Override
      public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
        final boolean callIsVirtual = (opcode == Opcodes.INVOKEVIRTUAL) || (opcode == Opcodes.INVOKEINTERFACE);
        reportMethodViolation(checkMethodAccess(owner, new Method(name, desc), callIsVirtual), "method body");
      }
      
      @Override
      public void visitFieldInsn(int opcode, String owner, String name, String desc) {
        reportMethodViolation(checkFieldAccess(owner, name), "method body");
      }
      
      @Override
      public void visitTypeInsn(int opcode, String type) {
        if (opcode == Opcodes.ANEWARRAY) {
          reportMethodViolation(checkType(Type.getObjectType(type)), "method body");
        }
      }
      
      @Override
      public void visitMultiANewArrayInsn(String desc, int dims) {
        reportMethodViolation(checkDescriptor(desc), "method body");
      }
      
      @Override
      public void visitLdcInsn(Object cst) {
        reportMethodViolation(checkConstant(cst, false), "method body");
      }
      
      @Override
      public void visitInvokeDynamicInsn(String name, String desc, Handle bsm, Object... bsmArgs) {
        final boolean isLambdaMetaFactory = LAMBDA_META_FACTORY_INTERNALNAME.equals(bsm.getOwner());
        reportMethodViolation(checkHandle(bsm, false), "method body");
        for (final Object cst : bsmArgs) {
          reportMethodViolation(checkConstant(cst, isLambdaMetaFactory), "method body");
        }
      }
      
      private String getHumanReadableMethodSignature() {
        final Type[] args = Type.getType(myself.getDescriptor()).getArgumentTypes();
        final StringBuilder sb = new StringBuilder(myself.getName()).append('(');
        boolean comma = false;
        for (final Type t : args) {
          if (comma) sb.append(',');
          sb.append(t.getClassName());
          comma = true;
        }
        sb.append(')');
        return sb.toString();
      }

      private void reportMethodViolation(ViolationResult violation, String where) {
        if (violation != null) {
          violations.add(new ForbiddenViolation(currentGroupId, myself, violation.message, String.format(Locale.ENGLISH, "%s of '%s'", where, getHumanReadableMethodSignature()), lineNo, violation.severity));
        }
      }
      
      @Override
      public void visitLineNumber(int lineNo, Label start) {
        this.lineNo = lineNo;
      }
    };
  }

  @Override
  public RecordComponentVisitor visitRecordComponent(final String name, final String desc, final String signature) {
    currentGroupId++;
    if (classSuppressed) {
      return null;
    }
    return new RecordComponentVisitor(Opcodes.ASM9) {
      {
        reportRecordComponentViolation(checkDescriptor(desc), "record component declaration");
      }
      
      @Override
      public AnnotationVisitor visitAnnotation(String desc, boolean visible) {
        final Type type = Type.getType(desc);
        maybeSuppressCurrentGroup(type);
        reportRecordComponentViolation(checkAnnotationDescriptor(type, visible), "annotation on record component declaration");
        return null;
      }

      @Override
      public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath, String desc, boolean visible) {
        reportRecordComponentViolation(checkAnnotationDescriptor(Type.getType(desc), visible), "type annotation on record component declaration");
        return null;
      }
      
      private void reportRecordComponentViolation(ViolationResult violationResult, String where) {
        if (violationResult != null) {
          violations.add(new ForbiddenViolation(currentGroupId, violationResult.message, String.format(Locale.ENGLISH, "%s of '%s'", where, name), -1, violationResult.severity));
        }
      }
    };
  }

  @Override
  public void visitEnd() {
    // fixup lambdas by assigning them the groupId where they were originally declared:
    for (final ForbiddenViolation v : violations) {
      if (v.targetMethod != null) {
        final Integer newGroupId = lambdas.get(v.targetMethod);
        if (newGroupId != null) {
          v.setGroupId(newGroupId.intValue());
        }
      }
    }
    // filter out suppressed groups
    if (!suppressedGroups.isEmpty()) {
      for (final Iterator<ForbiddenViolation> it = violations.iterator(); it.hasNext();) {
        final ForbiddenViolation v = it.next();
        if (suppressedGroups.get(v.getGroupId())) {
          it.remove();
        }
      }
    }
    // sort the violations by group id and later by line number:
    Collections.sort(violations);
    done = true;
  }
  
}