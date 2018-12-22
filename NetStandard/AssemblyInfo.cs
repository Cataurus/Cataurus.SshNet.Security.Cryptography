using System.Reflection;

#pragma warning disable CS7035 // The specified version string does not conform to the recommended format - major.minor.build.revision
[assembly: AssemblyFileVersion("1.0.0.0")]
#pragma warning restore CS7035 // The specified version string does not conform to the recommended format - major.minor.build.revision

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
