//
// Copyright © 2023 osy. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#import <pthread.h>
#import <stdio.h>
#import <TargetConditionals.h>
#import <unistd.h>
#import "QEMULogging.h"

static QEMULogging *gLoggingInstance;

void QEMUKitLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *line = [[NSString alloc] initWithFormat:[format stringByAppendingString:@"\n"] arguments:args];
    [[QEMULogging sharedInstance] writeLine:line];
    va_end(args);
    NSLog(@"%@", line);
}

@interface QEMULogging ()

@property (nonatomic, readwrite) NSPipe *standardOutput;
@property (nonatomic, readwrite) NSPipe *standardError;
@property (nonatomic, nullable) NSOutputStream *fileOutputStream;
@property (nonatomic, nullable) NSFileHandle *originalStdoutWrite;
@property (nonatomic, nullable) NSFileHandle *originalStderrWrite;

@end

@implementation QEMULogging

+ (void)initialize {
    static BOOL initialized = NO;
    if (!initialized) {
        initialized = YES;
        gLoggingInstance = [[QEMULogging alloc] init];
#if TARGET_OS_IPHONE // not supported on macOS
        [gLoggingInstance redirectStandardFds];
#endif
    }
}

+ (QEMULogging *)sharedInstance {
    return gLoggingInstance;
}

- (instancetype)init {
    if (self = [super init]) {
        __weak typeof(self) _weakSelf = self;
        self.standardOutput = [NSPipe pipe];
        __block NSString *outBuffer = [NSString string];
        self.standardOutput.fileHandleForReading.readabilityHandler = ^(NSFileHandle *handle) {
            typeof(self) _self = _weakSelf;
            NSData *data = [handle availableData];
            @try {
                [_self.originalStdoutWrite writeData:data];
            } @catch (NSException *e) {
                // fd closed on us
                _self.originalStdoutWrite = nil;
            }
            [_self.fileOutputStream write:data.bytes maxLength:data.length];
            NSArray<NSString *> *lines = [_self parseLinesFromData:data buffer:&outBuffer];
            for (NSString *line in lines) {
                [_self.delegate logging:_self didRecieveOutputLine:line];
            }
        };
        self.standardError = [NSPipe pipe];
        __block NSString *errorBuffer = [NSString string];
        self.standardError.fileHandleForReading.readabilityHandler = ^(NSFileHandle *handle) {
            typeof(self) _self = _weakSelf;
            NSData *data = [handle availableData];
            @try {
                [_self.originalStderrWrite writeData:data];
            } @catch (NSException *e) {
                // fd closed on us
                _self.originalStderrWrite = nil;
            }
            [_self.fileOutputStream write:data.bytes maxLength:data.length];
            NSArray<NSString *> *lines = [_self parseLinesFromData:data buffer:&errorBuffer];
            for (NSString *line in lines) {
                [_self.delegate logging:_self didRecieveErrorLine:line];
            }
        };
    }
    return self;
}

- (BOOL)redirectStandardFds {
    int real_stdout = -1;
    int real_stderr = -1;
    if ((real_stdout = dup(STDOUT_FILENO)) < 0) {
        perror("dup");
        goto error;
    }
    if ((real_stderr = dup(STDERR_FILENO)) < 0) {
        perror("dup");
        goto error;
    }
    if (dup2(self.standardOutput.fileHandleForWriting.fileDescriptor, STDOUT_FILENO) < 0) {
        perror("dup2");
        goto error;
    }
    if (dup2(self.standardError.fileHandleForWriting.fileDescriptor, STDERR_FILENO) < 0) {
        perror("dup2");
        goto error;
    }
    [self.standardOutput.fileHandleForWriting closeFile];
    [self.standardError.fileHandleForWriting closeFile];
    self.originalStdoutWrite = [[NSFileHandle alloc] initWithFileDescriptor:real_stdout closeOnDealloc:YES];
    self.originalStderrWrite = [[NSFileHandle alloc] initWithFileDescriptor:real_stderr closeOnDealloc:YES];
    return YES;
error:
    close(real_stdout);
    close(real_stderr);
    self.originalStdoutWrite = nil;
    self.originalStderrWrite = nil;
    return NO;
}

- (NSArray<NSString *> *)parseLinesFromData:(NSData *)data buffer:(NSString **)buffer {
    NSString *line = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!line) {
        return @[];
    }
    NSString *string = [*buffer stringByAppendingString:line];
    NSArray *lines = [string componentsSeparatedByString:@"\n"];
    *buffer = [lines lastObject];
    if (lines.count > 0) {
        lines = [lines subarrayWithRange:NSMakeRange(0, lines.count - 1)];
    }
    return lines;
}

- (void)logToFile:(NSURL *)path {
    [self endLog];
    NSOutputStream *stream = [NSOutputStream outputStreamWithURL:path append:NO];
    [stream open];
    __weak typeof(stream) weakStream = stream;
    atexit_b(^{
        NSStreamStatus status = weakStream.streamStatus;
        if (status == NSStreamStatusOpen || status == NSStreamStatusWriting) {
            [weakStream close];
        }
    });
    self.fileOutputStream = stream;
}

- (void)endLog {
    [self.fileOutputStream close];
    self.fileOutputStream = nil;
}

- (void)writeLine:(NSString *)line {
    [self.fileOutputStream write:(void *)[line cStringUsingEncoding:NSASCIIStringEncoding] maxLength:line.length];
}

@end
