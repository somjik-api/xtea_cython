import sys
import platform
from setuptools import setup, Extension
from Cython.Build import cythonize

# Simple platform-specific optimization flags
# Keep it portable - let the compiler defaults handle architecture-specific optimizations
if sys.platform == "win32":
    # Windows - use MSVC flags
    extra_compile_args = ["/O2"]
    extra_link_args = []
else:
    # macOS and Linux - use portable GCC/Clang flags
    extra_compile_args = ["-O3", "-ffast-math", "-funroll-loops"]
    extra_link_args = ["-flto"] if sys.platform != "darwin" else []

extensions = [
    Extension(
        "xtea_cython.core",
        sources=["core.pyx"],
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    ),
    Extension(
        "xtea_cython.batch",
        sources=["batch.pyx", "xtea_batch.c"],
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
