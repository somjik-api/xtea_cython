import sys
import platform
from setuptools import setup, Extension
from Cython.Build import cythonize

# Platform-specific optimization flags
is_x86 = platform.machine() in ("x86_64", "AMD64", "i686", "x86")

if sys.platform == "darwin":
    # macOS - use clang flags
    extra_compile_args = [
        "-O3",
        "-march=native",
        "-ffast-math",
        "-funroll-loops",
    ]
    extra_link_args = []
    # SSE2 only on x86
    if is_x86:
        extra_compile_args.append("-msse2")
elif sys.platform == "win32":
    # Windows - use MSVC flags
    if is_x86:
        extra_compile_args = ["/O2", "/GL", "/arch:SSE2"]
    else:
        extra_compile_args = ["/O2"]
    extra_link_args = ["/LTCG"]
else:
    # Linux and others - use GCC flags
    extra_compile_args = [
        "-O3",
        "-march=native",
        "-mtune=native",
        "-ffast-math",
        "-funroll-loops",
        "-fomit-frame-pointer",
    ]
    extra_link_args = ["-flto"]
    if is_x86:
        extra_compile_args.append("-msse2")

extensions = [
    Extension(
        "xtea_cython.core",
        sources=["core.pyx"],
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    ),
    Extension(
        "xtea_cython.simd",
        sources=["simd.pyx", "xtea_simd.c"],
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    )
]

setup(
    name="xtea_cython",
    version="0.1.0",
    description="XTEA encryption with multiple modes (ECB, CBC, CFB, OFB, CTR) - Cython implementation",
    author="",
    packages=["xtea_cython"],
    package_dir={"xtea_cython": "."},
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
            "cdivision": True,
            "initializedcheck": False,
            "nonecheck": False,
            "profile": False,
        },
    ),
    python_requires=">=3.8",
)
