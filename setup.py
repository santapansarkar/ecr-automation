from setuptools import setup, find_packages

setup(
    name='ecr_vul_image',
    version='0.1.0',
    author='Santapan Sarkar',
    author_email='santapansarkar@gmail.com',
    description='A package for scanning ECR images for vulnerabilities',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/santapansarkar/ecr-automation',
    packages=find_packages(),
    install_requires=[
        'boto3',
        'argparse',
        # Add any other dependencies your package needs
    ],
    entry_points={
        'console_scripts': [
            'ecr_vul_image=ecr_vul_image.__main__:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    python_requires='>=3.6',
)
