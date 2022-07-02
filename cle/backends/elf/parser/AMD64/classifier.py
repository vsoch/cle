from .register_class import RegisterClass
from .allocators import RegisterAllocator
from ...types import ClassType, types

import json
import hashlib
import copy


class Classification:
    def __init__(self, name, regclass):
        self.regclass = regclass
        self.name = name


class Eightbyte:
    def __init__(self):
        self.fields = []
        self.size = 0
        self.regclass = RegisterClass.NO_CLASS

    def has_space_for(self, f):
        return self.size + f.get("size", 0) <= 8

    def add(self, f, type_uid):
        self.size += f.get("size", 0)

        # Don't add original reference so it mucks up types
        f = copy.deepcopy(f)
        f["type_uid"] = type_uid
        self.fields.append(f)

    def do_print(self):
        for f in self.fields:
            print("{%s,%s}" % (f.get("name"), f.get("size", 0)))


def update_types(typ):
    """
    As we add register classes, we generate new types. Ideally
    we can separate the types from the registers, but this is a quick
    fix for now.
    """
    global types
    dumped = json.dumps(typ, sort_keys=True)
    uid = hashlib.md5(dumped.encode("utf-8")).hexdigest()
    types[uid] = typ
    return types


def classify_pointer():
    return Classification("Pointer", RegisterClass.INTEGER)


def classify(typ, return_classification=False, allocator=None):
    """
    Main entrypoint to classify something - we return a location string (for non
    aggregate types) OR an updated types that includes new locations for aggregates.
    """

    # Don't handle this case right now
    if not typ or "class" not in typ or typ["class"] in ["Unknown", "ComplexUnknown"]:
        return

    cls = None
    if typ.get("class") == "Pointer":
        cls = classify_pointer()

    elif typ["class"] in [
        "Scalar",
        "Integer",
        "Integral",
        "Float",
        "ComplexFloat",
        "Boolean",
    ]:
        cls = classify_scalar(typ)
    elif typ["class"] == "Enum":
        cls = classify_enum(typ)
    elif typ["class"] == "Struct":
        cls = classify_struct(typ, allocator=allocator)
    elif typ["class"] == "Union":
        cls = classify_union(typ, allocator=allocator)
    elif typ["class"] == "Array":
        cls = classify_array(typ, allocator=allocator)

        # If we don't know the underlying type
        if not cls:
            return

    elif typ["class"] == "Class":
        cls = classify_class(typ, allocator=allocator)
    elif typ["class"] == "Function":

        # Functions that aren't pointers
        cls = classify_function(typ)
        if not cls:
            return

    # https://refspecs.linuxbase.org/elf/x86_64-abi-0.21.pdf
    # A null pointer (for all types) has the value zero p 12 ABI document
    elif typ["class"] == "Unspecified" and typ.get("size") == 0:
        return "nullptr"

    if cls is None:
        # This should be IPython for further inspection
        return

    # Intermediate call if we need to return classification
    if isinstance(cls, Classification) and return_classification:
        return cls

    if isinstance(cls.regclass, RegisterClass):
        return allocator.get_register_string(reg=cls.regclass, size=typ.get("size", 0))

    # We are returning an aggregate
    for eb in cls.regclass:
        loc = allocator.get_register_string(reg=eb.regclass, size=8)
        for field in eb.fields:
            field["location"] = loc
    return cls


def classify_scalar(typ, size=None):
    """
    Classify a scalar type
    """
    # size in BITS
    size = size or typ.get("size", 0) * 8

    # Integral types
    if typ["class"] in ["Integer", "Boolean"]:  # TODO props.is_UTF?
        if size > 128:

            # TODO this should be some kind of eightbytes thing?
            raise ValueError("We don't know how to classify IntegerVec size > 128")

        if size == 128:
            # __int128 is treated as struct{long,long};
            # This is NOT correct, but we don't handle aggregates yet.
            # How do we differentiate between __int128 and __m128i?
            raise ValueError("We don't know how to classify IntegerVec size 128")

        # _Decimal32, _Decimal64, and __m64 are supposed to be SSE.
        # TODO How can we differentiate them here?
        return Classification("Integer", RegisterClass.INTEGER)

    if typ["class"] in ["Float", "ComplexFloat"]:
        if typ["class"] == "ComplexFloat":

            # x87 `complex long double`
            # These are wrong
            if size == 128:
                Classification("ComplexFloat", RegisterClass.COMPLEX_X87)

            # This is NOT correct.
            # TODO It should be struct{T r,i;};, but we don't handle aggregates yet
            return Classification("ComplexFloat", RegisterClass.MEMORY)

        if size <= 64:
            # 32- or 64-bit floats
            return Classification("Float", RegisterClass.SSE)

        if size == 128:
            # x87 `long double` OR __m128[d]
            # TODO: How do we differentiate the vector type here? Dyninst should help us
            return Classification("Float", RegisterClass.X87)

        if size > 128:
            return Classification("FloatVec", RegisterClass.SSE)

    # // TODO we will eventually want to throw this
    # // throw std::runtime_error{"Unknown scalar type"};
    return Classification("Unknown", RegisterClass.NO_CLASS)


def merge(first, second):
    """
    Page 21 (bottom) AMD64 ABI - method to come up with final classification based on two
    """
    # a. If both classes are equal, this is the resulting class.
    if first == second:
        return first

    # b. If one of the classes is NO_CLASS, the resulting class is the other
    if first == RegisterClass.NO_CLASS:
        return second

    if second == RegisterClass.NO_CLASS:
        return first

    # (c) If one of the classes is MEMORY, the result is the MEMORY class.
    if second == RegisterClass.MEMORY or first == RegisterClass.MEMORY:
        return RegisterClass.MEMORY

    # (d) If one of the classes is INTEGER, the result is the INTEGER.
    if second == RegisterClass.INTEGER or first == RegisterClass.INTEGER:
        return RegisterClass.INTEGER

    # (e) If one of the classes is X87, X87UP, COMPLEX_X87 class, MEMORY is used as class.
    if (
        second == RegisterClass.X87
        or second == RegisterClass.X87UP
        or second == RegisterClass.COMPLEX_X87
    ):
        return RegisterClass.MEMORY

    if (
        first == RegisterClass.X87
        or first == RegisterClass.X87UP
        or first == RegisterClass.COMPLEX_X87
    ):
        return RegisterClass.MEMORY

    # (f) Otherwise class SSE is used.
    return RegisterClass.SSE


def post_merge(lo, hi, size):
    """
    Page 22 AMD64 ABI point 5 - this is the most merger "cleanup"
    """
    # (a) If one of the classes is MEMORY, the whole argument is passed in memory.
    if lo == RegisterClass.MEMORY or hi == RegisterClass.MEMORY:
        lo = RegisterClass.MEMORY
        hi = RegisterClass.MEMORY

    # (b) If X87UP is not preceded by X87, the whole argument is passed in memory.
    if hi == RegisterClass.X87UP and lo != RegisterClass.X87:
        lo = RegisterClass.MEMORY
        hi = RegisterClass.MEMORY

    # (c) If the size of the aggregate exceeds two eightbytes and the first eight- byte isn’t SSE
    # or any other eightbyte isn’t SSEUP, the whole argument is passed in memory.
    if size > 128 and (lo != RegisterClass.SSE or hi != RegisterClass.SSEUP):
        lo = RegisterClass.MEMORY
        hi = RegisterClass.MEMORY

    # (d) If SSEUP is // not preceded by SSE or SSEUP, it is converted to SSE.
    if (
        hi == RegisterClass.SSEUP
        and lo != RegisterClass.SSE
        and lo != RegisterClass.SSEUP
    ):
        hi = RegisterClass.SSE
    return lo, hi


def classify_struct(typ, allocator=None, return_classification=False):
    return classify_aggregate(typ, allocator, return_classification, "Struct")


def classify_class(typ, allocator=None, return_classification=False):
    return classify_aggregate(typ, allocator, return_classification, "Class")


def classify_aggregate(
    typ, allocator=None, return_classification=False, aggregate="Struct"
):
    size = typ.get("size", 0)
    global types

    # If an object is larger than eight eightbyes (i.e., 64) class MEMORY.
    # Note there is a double check here because we don't have faith in the size field
    if size > 64:
        return Classification(aggregate, RegisterClass.MEMORY)

    ebs = []
    cur = Eightbyte()
    fields = copy.deepcopy(typ.get("fields", []))
    while fields:
        f = fields.pop(0)
        field = types.get(f.get("type"))
        if not field:
            continue

        # If we have another aggregate (I'm not sure this is correct)
        if field.get("class") in ["Union", "Struct", "Class"]:
            fields = copy.deepcopy(field.get("fields", [])) + fields
            continue

        if not cur.has_space_for(field):
            ebs.append(cur)
            cur = Eightbyte()

        # Store the type uid with the field
        cur.add(field, f.get("type"))

    # If we didn't add the current eightbyte
    if cur.size > 0:
        ebs.append(cur)

    # If the size of an object is larger than eight eightbytes it has class MEMORY
    # This is the double check
    if len(ebs) >= 8:
        return Classification(aggregate, RegisterClass.MEMORY)

    # TODO if it has un-aligned fields, also memory

    # There should be one classification per eightbyte
    for eb in ebs:

        # Empty structures
        if not eb.fields:
            continue

        fields = copy.deepcopy(eb.fields)
        merged = None
        while fields:

            # We can combine / merge two fields
            if len(fields) >= 2:
                field1 = fields.pop(0)
                field2 = fields.pop(0)
                c1 = classify(
                    field1,
                    allocator=allocator,
                    return_classification=True,
                )
                c2 = classify(
                    field2,
                    allocator=allocator,
                    return_classification=True,
                )
                merged = merge(c1.regclass, c2.regclass)
            else:
                field1 = fields.pop(0)
                c1 = classify(
                    field1,
                    allocator=allocator,
                    return_classification=True,
                ).regclass
                if merged:
                    merged = merge(merged, c1)
                else:
                    merged = c1
        eb.regclass = merged
        # Here we need to update each field

    return Classification(aggregate, ebs)


def classify_union(typ, allocator):
    """
    Matt's model does not account for unions
    """
    return Classification("Union", RegisterClass.MEMORY)


def classify_array(typ, allocator):
    size = typ.get("size", 0)
    global types

    # If size > 64 or unaligned fields, class memory
    if size > 64:
        return Classification("Array", RegisterClass.MEMORY)

    typename = typ.get("type")
    classname = None

    # regular class id or pointer
    while len(typename) == 32:
        newtype = types[typename]
        if "type" in newtype:
            typename = newtype["type"]
        elif "class" in newtype:
            classname = newtype["class"]
            break

    if not classname:
        classname = ClassType.get(typename)

    # Just classify the base type
    base_type = {"class": classname, "size": size}
    return classify(base_type, allocator=allocator, return_classification=True)


def classify_enum(typ):
    return Classification("Enum", RegisterClass.INTEGER)


def classify_function(typ, count):
    # auto [underlying_type, ptr_cnt] = unwrap_underlying_type(t);
    if count > 0:
        return classify_pointer(count)
    # Return no class
