using System.Reflection;

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
