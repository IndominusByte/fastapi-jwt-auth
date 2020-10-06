import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="fastapi-jwt-auth",
    version="0.2.0-beta",
    author="Nyoman Pradipta Dewantara",
    author_email="nyomanpradipta120@gmail.com",
    description="FastAPI extension that provides JWT Auth support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/IndominusByte/fastapi-jwt-auth",
    packages=setuptools.find_packages(),
    zip_safe=False,
    install_requires=[
        'fastapi>=0.61.0',
        'PyJWT>=1.7.1'
    ],
    classifiers=[
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    python_requires='>=3.6',
)
