
var openPtr = Module.findExportByName("libSystem.B.dylib", "open");
var fopenPtr = Module.findExportByName("libSystem.B.dylib", "fopen");
var accessPtr = Module.findExportByName("libSystem.B.dylib", "access");
var opendirPtr = Module.findExportByName("libSystem.B.dylib", "opendir");
var writePtr = Module.findExportByName("libSystem.B.dylib", "write");
var statPtr = Module.findExportByName("libSystem.B.dylib", "stat");
var strcasecmpPtr = Module.findExportByName("libSystem.B.dylib", "strcasecmp");
var strcmpPtr = Module.findExportByName("libSystem.B.dylib", "strcmp");
var forkPtr = Module.findExportByName("libSystem.B.dylib", "fork");
var systemPtr = Module.findExportByName("libSystem.B.dylib", "system");
var pthreadPtr = Module.findExportByName("libSystem.B.dylib", "pthread");
var bindPtr = Module.findExportByName("libSystem.B.dylib", "bind");
//var chdirPtr = Module.findExportByName("libSystem.B.dylib", "chdirPtr");

console.log('>>>> Start Native Hooking <<<<');
console.log('[+] find open() address: ' + openPtr.toString());
console.log('[+] find fopen() address: ' + fopenPtr.toString());
console.log('[+] find access() address: ' + accessPtr.toString());
console.log('[+] find stat() address: ' + statPtr.toString());
console.log('[+] find strcasecmp() address: ' + strcasecmpPtr.toString());
console.log('[+] find strcmp() address: ' + strcmpPtr.toString());
console.log('[+] find opendir() address: ' + opendirPtr.toString());
console.log('[+] find write() address: ' + writePtr.toString());
console.log('[+] find fork() address: ' + forkPtr.toString());
console.log('[+] find system() address: ' + systemPtr.toString());
console.log('[+] find bind() address: ' + bindPtr.toString());
//console.log('[+] find chdir() address: ' + chdirPtr.toString());

var jailbreakPaths = [
	"/proc/",
	"LaunchDaemons",
	"DynamicLibraries",
	"/etc/apt",
	"xCon",
	"tsProtector",
	"/etc/fstab",
	"saurik",
	"MobileSubstrate",
	"mobilesubstrate",
	"Cydia.app",
	"cydia",
	"blackra1n.app",
	"AddressBook.sqlitedb",
	"FakeCarrier.app",
	"Icy.app",
	"IntelliScreen.app",
	"MxTube.app",
	"RockApp.app",
	"/private/var/lib/apt",
	"Terminal.app",
	"Kirikae.app",
	"Lockdown.app",
	"Categories.app",
	"Backgrounder.app",
	"/bin/gzip",
	"/System/Library/KeyboardDictionaries",
	"/bin/gunzip",
	"/bin/tar",
	"/var/stash",
	"bin/sshd",
	"SBSettings",
	"WinterBoard.app",
	"/usr/libexec/sftp-server",
	"/var/log/syslog",
	"/bin/bash",
	"/bin/sh",
	"/etc/ssh/sshd_config",
	"/usr/libexec/ssh-keysign",
	"/boot/"
];

Interceptor.attach(openPtr, {
    onEnter: function (args) {
        fname = Memory.readCString(args[0])
        //console.log("open(" + fname + ",...)");
        jailbreakPaths.forEach(function(keyword){
            if(fname.indexOf(keyword)>=0){
                send("[+] Jailbreak detection : open(" + fname +") => nono" );
                Memory.protect(args[0], 100, 'rw-');
                Memory.writeUtf8String(args[0], "nono");
            }
        });
    },
    onLeave: function (retval) {    }
});

Interceptor.attach(opendirPtr, {
    onEnter: function (args) {
        fname = Memory.readCString(args[0])
        //console.log("opendir(" + fname + ",...)");
        jailbreakPaths.forEach(function(keyword){
            if(fname.indexOf(keyword)>=0){
                send("[+] Jailbreak detection : opendir(" + fname +") => nono");
                Memory.protect(args[0], 100, 'rw-');
                Memory.writeUtf8String(args[0], "nono"); 
            }
        });
    },
    onLeave: function (retval) {    }
});

Interceptor.attach(strcasecmpPtr, {
    onEnter: function (args) {
        //str1 = Memory.readCString(args[0]);
        //str2 = Memory.readCString(args[1]);
        //if (str1.indexOf('/') >= 0){
       // 	console.log("[+] strcasecmp(" + str1.toString() + ", " + str2.toString() + ")");
        //}
    },
    onLeave: function (retval) {
    }
});

Interceptor.attach(strcmpPtr, {
    onEnter: function (args) {
        //str1 = Memory.readCString(args[0]);
        //str2 = Memory.readCString(args[1]);
        //if (str1.indexOf('/') >= 0){
       // 	console.log("[+] strcmp(" + str1.toString() + ", " + str2.toString() + ")");
        //}
    },
    onLeave: function (retval) {
        //retval.replace(1);
    }
});

Interceptor.attach(bindPtr, {
    onEnter: function (args) {
        console.log("[+] bind(" + path.toString() + ")");
    },
    onLeave: function (retval) {
        //retval.replace(1);
    }
});

Interceptor.attach(fopenPtr, {
    onEnter: function (args) {
        fname = Memory.readCString(args[0]);
        jailbreakPaths.forEach(function(keyword){
            if(fname.indexOf(keyword) >= 0){
                send("[+] Jailbreak detection : fopen(" + fname +") => nono");
                //this.jailbreakCall = true;
                Memory.protect(args[0], 100, 'rw-');
                Memory.writeUtf8String(args[0], "/tmp/nono");
            }
        });
        //
    },
    onLeave: function (retval) {
    }
});

Interceptor.attach(accessPtr, {
    onEnter: function (args) {
        fname = Memory.readCString(args[0]);
        //console.log("!!!!! access(" + fname + ",...)");
        jailbreakPaths.forEach(function(keyword){
            if(fname.indexOf(keyword) >= 0){
                send("[+] Jailbreak detection : access(" + fname +")");
                Memory.protect(args[0], 100, 'rw-');
                Memory.writeUtf8String(args[0], "/tmp/nono");
            }
        });
        //
    },
    onLeave: function (retval) {
    }
});

Interceptor.attach(statPtr, {
    onEnter: function (args) {
        fname = Memory.readCString(args[0]);
        jailbreakPaths.forEach(function(keyword){
            if(fname.indexOf(keyword) >= 0){
                send("[+] Jailbreak detection : stat(" + fname +")");
                //Memory.protect(args[0], 100, 'rw-');
                Memory.writeUtf8String(args[0], "/tmp/nono");
            }
        });
        //
    },
    onLeave: function (retval) {
    }
});

Interceptor.attach(forkPtr, {
    onEnter: function (args) {
           console.log("fork()");
    },
    onLeave: function (retval) {
    }
});

Interceptor.attach(systemPtr, {
    onEnter: function (args) {
        console.log("system()");
    },
    onLeave: function (retval) {
    }
});

if(ObjC.available) {
	send("Jailbreak Detection enabled");
	for(var className in ObjC.classes) {
	    if (ObjC.classes.hasOwnProperty(className)) {
			//Jailbreak detection via accessing special files
			if(className == "NSFileManager") {
				send("Found our target class : " + className);
				var hook = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
				var hook2 = ObjC.classes.NSFileManager["- changeCurrentDirectoryPath:"];
				var hook3 = ObjC.classes.NSFileManager["- fileExistsAtPath:isDirectory:"];
				var hook4 = ObjC.classes.NSFileManager["- isReadableFileAtPath:"];
				var hook5 = ObjC.classes.NSFileManager["- destinationOfSymbolicLinkAtPath:error:"];
				//destinationOfSymbolicLinkAtPath:error:
				Interceptor.attach(hook.implementation, {
					onEnter: function (args) {
						var  path = ObjC.Object(args[2]).toString(); // NSString
						this.jailbreakCall = false;
						var i = jailbreakPaths.length;
						if (path.indexOf('.jpg')>=0||
							path.indexOf('.png')>=0||
							path.indexOf('/var/mobile/Containers/')>=0
							) { 
							return;
						}
						//send("fileExistsAtPath: " + path)
						while (i--) {
						    if (path.indexOf(jailbreakPaths[i]) >= 0){
								send("[+] Jailbreak detection : fileExistsAtPath(" + path + ")");
								this.jailbreakCall = true;
								break;
						    } 
						}
				    },
					onLeave: function (retval) {
						if(this.jailbreakCall) {
							retval.replace(0x00);
							//send("Jailbreak detection bypassed!");
						}
					}
				});
				Interceptor.attach(hook2.implementation, {
					onEnter: function (args) {
						send("[-] changeCurrentDirectoryPath");
				    }
				});
				Interceptor.attach(hook3.implementation, {
					onEnter: function (args) {
						var  path = ObjC.Object(args[2]).toString(); // NSString
						//send("[-] fileExistsAtPath:isDirectory: " + path);
				    }
				});
				Interceptor.attach(hook4.implementation, {
					onEnter: function (args) {
						var path = ObjC.Object(args[2]).toString(); // NSString
						this.jailbreakCall = false;
						var i = jailbreakPaths.length;
						if (path.indexOf('.jpg')>=0||
							path.indexOf('.png')>=0||
							path.indexOf('/var/mobile/Containers/')>=0
							) { 
							return;
						}
						//send("fileExistsAtPath: " + path)
						while (i--) {
						    if (path.indexOf(jailbreakPaths[i]) >= 0){
								send("[+] Jailbreak detection : isReadableFileAtPath(" + path + ")");
								this.jailbreakCall = true;
								break;
						    } 
						}
				    },
					onLeave: function (retval) {
						if(this.jailbreakCall) {
							retval.replace(0x00);
							//send("Jailbreak detection bypassed!");
						}
					}
				});
				Interceptor.attach(hook4.implementation, {
					onEnter: function (args) {
						var path = ObjC.Object(args[2]).toString(); // NSString
						this.jailbreakCall = false;
						var i = jailbreakPaths.length;
						if (path.indexOf('.jpg')>=0||
							path.indexOf('.png')>=0||
							path.indexOf('/var/mobile/Containers/')>=0
							) { 
							return;
						}
						//send("fileExistsAtPath: " + path)
						while (i--) {
						    if (path.indexOf(jailbreakPaths[i]) >= 0){
								send("[+] Jailbreak detection : destinationOfSymbolicLinkAtPath:error:(" + path + ")");
								this.jailbreakCall = true;
								break;
						    } 
						}
				    },
					onLeave: function (retval) {
						if(this.jailbreakCall) {
							retval.replace(0x00);
							//send("Jailbreak detection bypassed!");
						}
					}
				});
			}

			if(className == "ams2Library") {
			    send("Found our target class : " + className);

				var hook = ObjC.classes.ams2Library["- a3142:"];
				Interceptor.attach(hook.implementation, {
					onEnter: function (args) {
						send("[-] -[ams2Library a3142:] ");
				  	}
				});
			}

			if(className == "amsLibrary") {
			    send("Found our target class : " + className);

				var hook = ObjC.classes.ams2Library["- a3142:"];
				Interceptor.attach(hook.implementation, {
					onEnter: function (args) {
						send("[-] -[amsLibrary a3142:] ");
				  	}
				});
			}

			//Jailbreak detection via writing to forbidden paths
			if(className == "NSString") {
			    send("Found our target class : " + className);

					var hook = ObjC.classes.NSString["- writeToFile:atomically:"];
					Interceptor.attach(hook.implementation, {
					onEnter: function (args) {
						var  path = ObjC.Object(args[2]).toString(); // NSString
						send("NSString : " + path);

						if (path.indexOf("private") >= 0) {
									send("[+] Jailbreak detection : writeToFile("+path+")");
									this.jailbreakCall = true;
									this.error = args[5];
						}
				  },
					onLeave: function (retval) {
						if(this.jailbreakCall) {
							var error = ObjC.classes.NSError.alloc();
							Memory.writePointer(this.error, error);
							//send("Jailbreak detection bypassed!");
						}
				  }
				});
			}
					//Jailbreak detection via cydia URL Schema
			if(className == "UIApplication") {
			    send("Found our target class : " + className);
				var hook = ObjC.classes.UIApplication["- canOpenURL:"];
				Interceptor.attach(hook.implementation, {
					onEnter: function (args) {
						var  url = ObjC.Object(args[2]).toString(); // NSString
						send("URL : " + url);
						if (url.indexOf("cydia") >= 0) {
									send("Jailbreak detection : canOpenURL("+url+")");
									this.jailbreakCall = true;
						}
					},
					onLeave: function (retval) {
						if(this.jailbreakCall) {
							retval.replace(0x00);
							//send("Jailbreak detection bypassed!");
						}
				  	}
				});
			}

			if(className == "BTWCGXMLParser") {
			    send("Found our target class : " + className);

				var hook = ObjC.classes.BTWCGXMLParser["- checkRootingWithRCL:"];
				var hook2 = ObjC.classes.BTWCGXMLParser["- checkRooting:"];
				var hook3 = ObjC.classes.BTWCGXMLParser["- isJailBroken"];

				Interceptor.attach(hook.implementation, {
					onEnter: function (args) {
						var  url = ObjC.Object(args[2]).toString(); // NSString
						send("[-] -[BTWCGXMLParser checkRootingWithRCL:]");
				  	},
					onLeave: function (retval) {
					}
				});
				Interceptor.attach(hook2.implementation, {
					onEnter: function (args) {
						var  url = ObjC.Object(args[2]).toString(); // NSString
						send("[-] -[BTWCGXMLParser checkRooting:] (" + url + ")");
				  	},
					onLeave: function (retval) {
					}
				});
				Interceptor.attach(hook3.implementation, {
					onEnter: function (args) {
						//var  url = ObjC.Object(args[2]).toString(); // NSString
						send("[-] -[BTWCGXMLParser isJailBroken] ()");
				  	},
					onLeave: function (retval) {
					}
				});
			}

			if(className == "BTWCodeGuardManager") {
			    send("Found our target class : " + className);

				var hook = ObjC.classes.BTWCodeGuardManager["- setRootingInfo:"];
				var hook2 = ObjC.classes.BTWCodeGuardManager["- setRootingCheck:"];
				Interceptor.attach(hook.implementation, {
					onEnter: function (args) {
						var id = ObjC.Object(args[2]).toString(); // NSString
						send("[+] -[BTWCodeGuardManager setRootingInfo:] " + id);
				  	}
				});
				Interceptor.attach(hook2.implementation, {
					onEnter: function (args) {
						var id = ObjC.Object(args[2]).toString(); // NSString
						send("[+] -[BTWCodeGuardManager setRootingCheck:] " + id);
				  	}
				});
			}

			//BTWIPManager checkOpenPort:
			if(className == "Codeguard") {
			    send("Found our target class : " + className);

				var hook = ObjC.classes.Codeguard["- rootingCheck"];
				var hook2 = ObjC.classes.Codeguard["- setRootingInfo:"];
				//var hook3 = ObjC.classes.Codeguard["- setRootingInfo:"];
				Interceptor.attach(hook.implementation, {
					onEnter: function (args) {
						var id = ObjC.Object(args[2]).toString(); // NSString
						send("[+] -[BTWCodeGuardManager setRootingInfo:] " + id);
				  	}
				});
				Interceptor.attach(hook2.implementation, {
					onEnter: function (args) {
						var id = ObjC.Object(args[2]).toString(); // NSString
						send("[+] -[BTWCodeGuardManager setRootingCheck:] " + id);
				  	}
				});
			}

			if(className == "KSFileUtil") {
			    send("Found our target class : " + className);

				var hook = ObjC.classes.KSFileUtil["+ checkJailBreak"];
				Interceptor.attach(hook.implementation, {
					onEnter: function (args) {
						send("[+] -[KSFileUtil checkJailBreak] ");
				  	}
				});
			}

			if(className == "SWPhoneInfo") {
			    send("Found our target class : " + className);
				var hook = ObjC.classes.SWPhoneInfo["+ getResultSum:portNumber:connected:accessGroup:"];
				var hook2 = ObjC.classes.SWPhoneInfo["+ checkRoot:"];
				var hook3 = ObjC.classes.SWPhoneInfo["+ dbs7dns6dyd3"];
				Interceptor.attach(hook.implementation, {
					onEnter: function (args) {
						send("[+] -[SWPhoneInfo getResultSum:portNumber:connected:accessGroup:] ");
				  	}
				});
				Interceptor.attach(hook2.implementation, {
					onEnter: function (args) {
						send("[+] -[SWPhoneInfo checkRoot:] ");
						//send("send called from:" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n") + " ");
				  	},
				  	onLeave: function (retval) {
				  		send("[-] -[SWPhoneInfo checkRoot:] retval : " + retval.toString());
				  		retval.replace(0x00);
					}
				});
				Interceptor.attach(hook3.implementation, {
					onEnter: function (args) {
						send("[+] -[SWPhoneInfo dbs7dns6dyd3] ");
						//console.log("send called from:" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n") + " ");
				  	},
				  	onLeave: function (retval) {
				  		send("[-] -[SWPhoneInfo dbs7dns6dyd3] retval :" + retval.toString());
				  		retval.replace(0x00);
					}
				});
				//SWPhoneInfo dbs7dns6dyd3
				// checkRoot:
			}

// ams2Library
//  +[SWPhoneInfo getResultSum:portNumber:connected:accessGroup:]
// +[KSFileUtil checkJailBreak
			

	    }
	}
} else {
	console.log("Objective-C Runtime is not available!");
}



