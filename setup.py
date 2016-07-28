from setuptools import setup

setup(
    name='webpush-encryption',
    version='0.1.0',
    packages=[
        'webpush_encryption'
    ],
    url='https://github.com/mobify/webpush-payload-encryption',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Communications',
        'Topic :: Security :: Cryptography'
    ],
    author='messaging@mobify.com',
    author_email='messaging@mobify.com',
    description='Python package to handle the encryption of web push '
                'notifications for Firefox and Chrome',
    install_requires=[
        'cryptography>=1.3.2',
        'pyOpenSSL>=0.15.1'
    ],
    test_suite='nose.collector',
    tests_require=['nose', 'mock'],
)
