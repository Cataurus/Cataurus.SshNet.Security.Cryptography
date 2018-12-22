using System.Reflection;

[assembly: AssemblyCopyright("Copyright 2018 Ulf (Cataurus) Prill")]
[assembly: AssemblyCompany("Ulf (Cataurus) Prill")]
[assembly: AssemblyDescription("1.0.0.0 - 1.0.20181210.1")]
[assembly: AssemblyProduct("Cataurus.SshNet.Security.Cryptography")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: AssemblyVersion("1.0.0.0")]

#if NETSTANDARD1_0
[assembly: AssemblyInformationalVersion("1.0.0.0")]
#else
#if NETSTANDARD1_1
[assembly: AssemblyInformationalVersion("1.1.0.0")]
	#else
		#if NETSTANDARD1_2
		[assembly: AssemblyInformationalVersion("1.2.0.0")]
		#else
			#if NETSTANDARD1_3
			[assembly: AssemblyInformationalVersion("1.3.0.0")]
			#else
				#if NETSTANDARD2_0
				[assembly: AssemblyInformationalVersion("2.0.0.0")]
				#endif
			#endif
		#endif
	#endif
#endif
