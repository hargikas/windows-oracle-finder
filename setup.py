import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="windows-oracle-finder-hargikas", 
    version="0.2.1",
    author="Charalampos Gkikas",
    author_email="hargikas@gmail.com",
    description="A small package for windows machines to find where the installation of oracle client resides.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hargikas/windows-oracle-finder",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3',
    install_requires=['pefile', 'logzero', 'pywin32'],
)