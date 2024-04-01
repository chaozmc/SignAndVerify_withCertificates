// See https://aka.ms/new-console-template for more information

using SignAndVerify_withCertificates;
using System.Security.Cryptography.X509Certificates;

securityOperations sc1 = new securityOperations();
X509Certificate2 myCert = new X509Certificate2(sc1.GetCertificateFromLocalMachineStore("test"));

string signedString = sc1.generateSignatureB64("Hallo", myCert);

Console.WriteLine("The message 'Hallo' signed with the certificate 'test' is:");
Console.Write(signedString);
Console.Write('\n');
Console.Write('\n');
Console.Write('\n');
Console.Write('\n');
Console.WriteLine("The signature is verified: " + sc1.verifySignature("Hallo", signedString, myCert));
Console.Write('\n');
Console.Write('\n');
Console.Write('\n');
Console.Write('\n');










