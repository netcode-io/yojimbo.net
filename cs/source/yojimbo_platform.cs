/*
    Yojimbo Client/Server Network Library.

    Copyright © 2016 - 2019, The Network Protocol Company, Inc.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer 
           in the documentation and/or other materials provided with the distribution.

        3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived 
           from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;

namespace networkprotocol
{
    static partial class yojimbo
    {
        #region platform

        /**
            Sleep for approximately this number of seconds.
            @param time number of seconds to sleep for.
         */
        public static void sleep(double time)
        {
            var milliseconds = (int)(time * 1000);
            Thread.Sleep(milliseconds);
        }

        static readonly long time_start = Stopwatch.GetTimestamp();

        /**
            Get a high precision time in seconds since the application has started.
            Monotonic: does not jump with wall clock or daylight saving changes.
            Please store time in doubles so you retain sufficient precision as time increases.
            @returns Time value in seconds.
         */
        public static double time() =>
            (Stopwatch.GetTimestamp() - time_start) / (double)Stopwatch.Frequency;

        /**
            Get the current wall clock time in seconds since the unix epoch (C time()).
         */
        public static ulong ctime() => (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        #endregion

        #region assert / logging

        public const int LOG_LEVEL_NONE = 0;
        public const int LOG_LEVEL_ERROR = 1;
        public const int LOG_LEVEL_INFO = 2;
        public const int LOG_LEVEL_DEBUG = 3;

        static int log_level_ = 0;

        /**
            Set the yojimbo log level.
            Valid log levels are: YOJIMBO_LOG_LEVEL_NONE, YOJIMBO_LOG_LEVEL_ERROR, YOJIMBO_LOG_LEVEL_INFO and YOJIMBO_LOG_LEVEL_DEBUG
            @param level The log level to set. Initially set to YOJIMBO_LOG_LEVEL_NONE.
         */
        public static void log_level(int level)
        {
            log_level_ = level;
            netcode.log_level(level);
            reliable.log_level(level);
        }

        public static Action<string, string, string, int> assert_function = default_assert_handler;

        static void default_assert_handler(string condition, string function, string file, int line)
        {
            // We use LOG_LEVEL_NONE because it's lower than LOG_LEVEL_ERROR, so even if you suppress errors (by setting
            // log_level(LOG_LEVEL_NONE)), this will still be logged.
            printf(LOG_LEVEL_NONE, $"assert failed: ( {condition} ), function {function}, file {file}, line {line}\n");
            if (Debugger.IsAttached)
                Debugger.Break();
        }

        static Action<string> printf_function =
            x => Console.Write(x);

        /**
            Printf function used by yojimbo to emit logs.
            This function internally calls the printf callback set by the user. 
            @see yojimbo_set_printf_function
         */
#if YOJIMBO_ENABLE_LOGGING
        public static void printf(int level, string format)
        {
            if (level > log_level_) return;
            printf_function(format);
        }
#else
        public static void printf(int level, string format) { }
#endif

        /**
            Assert function used by yojimbo.
            This assert function lets the user override the assert presentation. Like upstream, the process exits after the assert handler returns.
            @see yojimbo_set_assert_function
         */
        [DebuggerStepThrough, Conditional("DEBUG")]
        public static void assert(bool condition, [CallerArgumentExpression(nameof(condition))] string conditionText = null, [CallerMemberName] string function = null, [CallerFilePath] string file = null, [CallerLineNumber] int line = 0)
        {
            if (!condition)
            {
                assert_function?.Invoke(conditionText, function, file, line);
                Environment.Exit(1);
            }
        }

        /**
            Call this to set the printf function to use for logging.
            @param function The printf callback function.
         */
        public static void set_printf_function(Action<string> function)
        {
            assert(function != null);
            printf_function = function;
            netcode.set_printf_function(function);
            reliable.set_printf_function(function);
        }

        /**
            Call this to set the function to call when an assert triggers.
            @param function The assert callback function.
         */
        public static void set_assert_function(Action<string, string, string, int> function)
        {
            assert_function = function;
            netcode.set_assert_function(function);
            reliable.set_assert_function(function);
        }

        #endregion
    }
}
