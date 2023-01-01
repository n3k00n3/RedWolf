// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System;
using System.Collections.Generic;

namespace RedWolf.Core
{
    public class RedWolfException : Exception
    {
        public RedWolfException() : base()
        {

        }
        public RedWolfException(string message) : base(message)
        {

        }
    }

    public class ControllerException : Exception
    {
        public ControllerException() : base()
        {

        }
        public ControllerException(string message) : base(message)
        {

        }
    }

    public class ControllerNotFoundException : Exception
    {
        public ControllerNotFoundException() : base()
        {

        }
        public ControllerNotFoundException(string message) : base(message)
        {

        }
    }

    public class ControllerBadRequestException : Exception
    {
        public ControllerBadRequestException() : base()
        {

        }
        public ControllerBadRequestException(string message) : base(message)
        {

        }
    }

    public class ControllerUnauthorizedException : Exception
    {
        public ControllerUnauthorizedException() : base()
        {

        }
        public ControllerUnauthorizedException(string message) : base(message)
        {

        }
    }

    public class RedWolfDirectoryTraversalException : Exception
    {
        public RedWolfDirectoryTraversalException() : base()
        {

        }
        public RedWolfDirectoryTraversalException(string message) : base(message)
        {

        }
    }

    public class RedWolfLauncherNeedsListenerException : RedWolfException
    {
        public RedWolfLauncherNeedsListenerException() : base()
        {

        }
        public RedWolfLauncherNeedsListenerException(string message) : base(message)
        {

        }
    }

    public class RedWolfCompileGrawlStagerFailedException : RedWolfException
    {
        public RedWolfCompileGrawlStagerFailedException() : base()
        {

        }
        public RedWolfCompileGrawlStagerFailedException(string message) : base(message)
        {

        }
    }
}
