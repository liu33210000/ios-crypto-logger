#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <objc/runtime.h>

// MARK: - Logger Interface

@interface LogManager : NSObject
@property (atomic, assign) BOOL isEnabled;
+ (instancetype)sharedInstance;
- (void)log:(NSString *)format, ...;
- (NSString *)getLogPath;
- (NSString *)getLogContent;
- (void)clearLogs;
@end

@implementation LogManager {
    NSFileHandle *_fileHandle;
    NSString *_logPath;
    dispatch_queue_t _writeQueue; // Serial queue for async writes
}

+ (instancetype)sharedInstance {
    static LogManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
    });
    return sharedInstance;
}

- (instancetype)init {
    if (self = [super init]) {
        // Create a dedicated serial queue for file writes (won't block caller)
        _writeQueue = dispatch_queue_create("com.cryptomonitor.logqueue", DISPATCH_QUEUE_SERIAL);
        
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *docsDir = [paths firstObject];
        _logPath = [docsDir stringByAppendingPathComponent:@"crypto_monitor.log"];
        _isEnabled = YES; // Default to enabled
        
        // Initialize file asynchronously to avoid blocking during load
        dispatch_async(_writeQueue, ^{
            @try {
                if (![[NSFileManager defaultManager] fileExistsAtPath:self->_logPath]) {
                    [@"" writeToFile:self->_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
                }
                self->_fileHandle = [NSFileHandle fileHandleForWritingAtPath:self->_logPath];
                [self->_fileHandle seekToEndOfFile];
            } @catch (NSException *e) {
                NSLog(@"[CryptoMonitor] Failed to init log file: %@", e);
            }
        });
    }
    return self;
}

- (void)log:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *logLine = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    NSString *timestampedLog = [NSString stringWithFormat:@"[%@] %@\n", [NSDate date], logLine];
    
    // Write asynchronously to not block the caller (hooks)
    dispatch_async(_writeQueue, ^{
        @try {
            if (self->_fileHandle) {
                NSData *data = [timestampedLog dataUsingEncoding:NSUTF8StringEncoding];
                [self->_fileHandle writeData:data];
            }
        } @catch (NSException *e) {
            // Silently ignore write failures to prevent crashes
        }
    });
    
    // Console log is fast, can stay synchronous -> REMOVED to prevent main thread blocking
    // NSLog(@"[CryptoMonitor] %@", logLine);
}

- (NSString *)getLogPath {
    return _logPath;
}

- (NSString *)getLogContent {
    __block NSString *content = @"";
    dispatch_sync(_writeQueue, ^{
        content = [NSString stringWithContentsOfFile:self->_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    });
    return content;
}

- (void)clearLogs {
    dispatch_async(_writeQueue, ^{
        @try {
            [@"" writeToFile:self->_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            [self->_fileHandle closeFile];
            self->_fileHandle = [NSFileHandle fileHandleForWritingAtPath:self->_logPath];
        } @catch (NSException *e) {
            NSLog(@"[CryptoMonitor] Failed to clear logs: %@", e);
        }
    });
}

@end

// MARK: - Utilities

// Max bytes to log per data block to prevent memory exhaustion
static const size_t kMaxLogDataLength = 256;

NSString *DataToHex(const void *data, size_t length) {
    if (!data || length == 0) return @"(null)";
    
    BOOL truncated = NO;
    size_t displayLength = length;
    if (displayLength > kMaxLogDataLength) {
        displayLength = kMaxLogDataLength;
        truncated = YES;
    }
    
    const unsigned char *buffer = (const unsigned char *)data;
    NSMutableString *hexString = [NSMutableString stringWithCapacity:displayLength * 2 + 20];
    for (size_t i = 0; i < displayLength; i++) {
        [hexString appendFormat:@"%02x", buffer[i]];
    }
    
    if (truncated) {
        [hexString appendFormat:@"...(%zu bytes total)", length];
    }
    return hexString;
}

// MARK: - Hooks

// 1. MD5
%hookf(unsigned char *, CC_MD5, const void *data, CC_LONG len, unsigned char *md) {
    if (![LogManager sharedInstance].isEnabled) return %orig;
    unsigned char *result = %orig(data, len, md);
    if (len > 0) {
        [[LogManager sharedInstance] log:@"[MD5] Input: %@ -> Hash: %@", DataToHex(data, len), DataToHex(result, CC_MD5_DIGEST_LENGTH)];
    }
    return result;
}

// 2. SHA256
%hookf(unsigned char *, CC_SHA256, const void *data, CC_LONG len, unsigned char *md) {
    if (![LogManager sharedInstance].isEnabled) return %orig;
    unsigned char *result = %orig(data, len, md);
    if (len > 0) {
        [[LogManager sharedInstance] log:@"[SHA256] Input: %@ -> Hash: %@", DataToHex(data, len), DataToHex(result, CC_SHA256_DIGEST_LENGTH)];
    }
    return result;
}

// 3. CCCrypt (AES/DES etc)
%hookf(CCCryptorStatus, CCCrypt, CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    if (![LogManager sharedInstance].isEnabled) return %orig;
    CCCryptorStatus status = %orig(op, alg, options, key, keyLength, iv, dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved);
    
    if (status == kCCSuccess) {
        NSString *algoName = (alg == kCCAlgorithmAES) ? @"AES" : (alg == kCCAlgorithmDES) ? @"DES" : [NSString stringWithFormat:@"Alg_%d", alg];
        NSString *opName = (op == kCCEncrypt) ? @"Encrypt" : @"Decrypt";
        
        [[LogManager sharedInstance] log:@"[%@] %@ Key: %@ IV: %@ In: %@ Out: %@",
         algoName, opName,
         DataToHex(key, keyLength),
         DataToHex(iv, (alg == kCCAlgorithmAES ? kCCBlockSizeAES128 : 8)), // Approximate IV len
         DataToHex(dataIn, dataInLength),
         DataToHex(dataOut, (dataOutMoved ? *dataOutMoved : 0))];
    }
    return status;
}

// 4. Base64 - with throttling to avoid performance issues
// Base64 is called VERY frequently by iOS system internals

static NSTimeInterval g_lastBase64Log = 0;
static const NSTimeInterval kBase64LogInterval = 1.0; // Increased to 1.0s to reduce lag

static NSString *TruncateString(NSString *str, NSUInteger maxLen) {
    if (str.length <= maxLen) return str;
    return [NSString stringWithFormat:@"%@...(+%lu chars)", [str substringToIndex:maxLen], (unsigned long)(str.length - maxLen)];
}

static BOOL ShouldLogBase64(void) {
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now - g_lastBase64Log >= kBase64LogInterval) {
        g_lastBase64Log = now;
        return YES;
    }
    return NO;
}

%hook NSData
- (id)initWithBase64EncodedString:(NSString *)base64String options:(NSDataBase64DecodingOptions)options {
    if (![LogManager sharedInstance].isEnabled) return %orig;
    id result = %orig;
    if (result && ShouldLogBase64()) {
        [[LogManager sharedInstance] log:@"[Base64Decode] In: %@ -> Out: %@", TruncateString(base64String, 128), DataToHex([result bytes], [result length])];
    }
    return result;
}

- (NSString *)base64EncodedStringWithOptions:(NSDataBase64EncodingOptions)options {
    if (![LogManager sharedInstance].isEnabled) return %orig;
    NSString *result = %orig;
    if (self.length > 0 && ShouldLogBase64()) {
        [[LogManager sharedInstance] log:@"[Base64Encode] In: %@ -> Out: %@", DataToHex([self bytes], [self length]), TruncateString(result, 128)];
    }
    return result;
}
%end


// MARK: - UI Components

@interface LogViewController : UIViewController
@property (nonatomic, strong) UITextView *textView;
@end

@implementation LogViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];
    
    // Title
    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 40, self.view.frame.size.width - 40, 30)];
    titleLabel.text = @"Crypto Monitor Logs";
    titleLabel.textColor = [UIColor greenColor];
    titleLabel.font = [UIFont boldSystemFontOfSize:20];
    titleLabel.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:titleLabel];
    
    // Buttons
    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.frame = CGRectMake(20, 80, 80, 30);
    [closeBtn setTitle:@"Close" forState:UIControlStateNormal];
    [closeBtn addTarget:self action:@selector(closeTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:closeBtn];
    
    UIButton *refreshBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    refreshBtn.frame = CGRectMake(110, 80, 80, 30);
    [refreshBtn setTitle:@"Reload" forState:UIControlStateNormal];
    [refreshBtn addTarget:self action:@selector(refreshLogs) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:refreshBtn];

    UIButton *exportBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    exportBtn.frame = CGRectMake(200, 80, 80, 30);
    [exportBtn setTitle:@"Export" forState:UIControlStateNormal];
    [exportBtn addTarget:self action:@selector(exportLogs) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:exportBtn];
    
    UIButton *clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    clearBtn.frame = CGRectMake(290, 80, 80, 30);
    [clearBtn setTitle:@"Clear" forState:UIControlStateNormal];
    [clearBtn setTitleColor:[UIColor redColor] forState:UIControlStateNormal];
    [clearBtn addTarget:self action:@selector(clearLogs) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:clearBtn];
    
    // Text View
    self.textView = [[UITextView alloc] initWithFrame:CGRectMake(10, 120, self.view.frame.size.width - 20, self.view.frame.size.height - 130)];
    self.textView.backgroundColor = [UIColor colorWithWhite:0.1 alpha:1.0];
    self.textView.textColor = [UIColor greenColor];
    self.textView.font = [UIFont fontWithName:@"Courier" size:12];
    self.textView.editable = NO;
    [self.view addSubview:self.textView];
    
    // Logging Toggle Switch
    UISwitch *logSwitch = [[UISwitch alloc] initWithFrame:CGRectMake(self.view.frame.size.width - 70, 40, 50, 30)];
    [logSwitch setOn:[LogManager sharedInstance].isEnabled];
    [logSwitch addTarget:self action:@selector(loggingSwitched:) forControlEvents:UIControlEventValueChanged];
    [self.view addSubview:logSwitch];
    
    // Switch Label
    UILabel *switchLabel = [[UILabel alloc] initWithFrame:CGRectMake(self.view.frame.size.width - 130, 45, 60, 20)];
    switchLabel.text = @"Active:";
    switchLabel.textColor = [UIColor whiteColor];
    switchLabel.font = [UIFont systemFontOfSize:12];
    switchLabel.textAlignment = NSTextAlignmentRight;
    [self.view addSubview:switchLabel];
    
    [self refreshLogs];
}

- (void)loggingSwitched:(UISwitch *)sender {
    [LogManager sharedInstance].isEnabled = sender.isOn;
}

- (void)closeTapped {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)refreshLogs {
    self.textView.text = [[LogManager sharedInstance] getLogContent];
    if (self.textView.text.length > 0) {
        [self.textView scrollRangeToVisible:NSMakeRange(self.textView.text.length - 1, 1)];
    }
}

- (void)clearLogs {
    [[LogManager sharedInstance] clearLogs];
    [self refreshLogs];
}

- (void)exportLogs {
    NSString *path = [[LogManager sharedInstance] getLogPath];
    NSURL *url = [NSURL fileURLWithPath:path];
    
    UIActivityViewController *activityVC = [[UIActivityViewController alloc] initWithActivityItems:@[url] applicationActivities:nil];
    
    // iPad popover fix
    if ([UIDevice currentDevice].userInterfaceIdiom == UIUserInterfaceIdiomPad) {
        activityVC.popoverPresentationController.sourceView = self.view;
        activityVC.popoverPresentationController.sourceRect = CGRectMake(self.view.frame.size.width/2, self.view.frame.size.height/2, 0, 0);
    }
    
    [self presentViewController:activityVC animated:YES completion:nil];
}

@end


// MARK: - Floating Window

@interface FloatingWindow : UIWindow
@end

@implementation FloatingWindow
- (BOOL)pointInside:(CGPoint)point withEvent:(UIEvent *)event {
    // Only capture touches on subviews that are userinteractive and not hidden
    for (UIView *view in self.subviews) {
        if (!view.hidden && view.userInteractionEnabled && [view pointInside:[self convertPoint:point toView:view] withEvent:event]) {
            // Special check: ensure we don't capture the root view itself if it's full screen
            if (view == self.rootViewController.view) {
                // Recursively check root view's subviews (the button)
                for (UIView *subview in view.subviews) {
                    if (!subview.hidden && subview.userInteractionEnabled && [subview pointInside:[view convertPoint:point toView:subview] withEvent:event]) {
                        return YES;
                    }
                }
                continue; // Don't return YES for the root view itself
            }
            return YES;
        }
    }
    return NO;
}
@end

@interface FloatingController : NSObject
@property (nonatomic, strong) FloatingWindow *window;
@property (nonatomic, strong) UIButton *button;
@property (nonatomic, assign) NSInteger retryCount;
@end

@implementation FloatingController

+ (instancetype)sharedInstance {
    static FloatingController *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
    });
    return sharedInstance;
}

- (void)setup {
    if (self.window != nil) return; // Already set up
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [self createWindowWithRetry];
    });
}

- (void)createWindowWithRetry {
    // Try to get a valid window scene (iOS 13+)
    UIWindowScene *scene = nil;
    
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (s.activationState == UISceneActivationStateForegroundActive && [s isKindOfClass:[UIWindowScene class]]) {
                scene = (UIWindowScene *)s;
                break;
            }
        }
        
        // Fallback: try any foreground scene
        if (!scene) {
            for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
                if ([s isKindOfClass:[UIWindowScene class]]) {
                    scene = (UIWindowScene *)s;
                    break;
                }
            }
        }
        
        if (!scene) {
            // No scene yet, retry after a delay (max 10 retries = 10 seconds)
            if (self.retryCount < 10) {
                self.retryCount++;
                NSLog(@"[CryptoMonitor] No active scene yet, retry %ld...", (long)self.retryCount);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    [self createWindowWithRetry];
                });
            } else {
                NSLog(@"[CryptoMonitor] Failed to find scene after 10 retries");
            }
            return;
        }
        
        self.window = [[FloatingWindow alloc] initWithWindowScene:scene];
    } else {
        // iOS 12 and below
        self.window = [[FloatingWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    }
    
    self.window.windowLevel = UIWindowLevelAlert + 100;
    self.window.backgroundColor = [UIColor clearColor];
    self.window.rootViewController = [[UIViewController alloc] init];
    self.window.rootViewController.view.backgroundColor = [UIColor clearColor];
    self.window.rootViewController.view.userInteractionEnabled = NO; // CRITICAL: Let touches pass through root view
    self.window.hidden = NO;
    
    // Make sure window is key and visible
    if (@available(iOS 15.0, *)) {
        // iOS 15+ needs makeKeyAndVisible for proper interaction
        [self.window makeKeyAndVisible];
    }
    
    self.button = [UIButton buttonWithType:UIButtonTypeCustom];
    self.button.frame = CGRectMake(20, 100, 50, 50);
    self.button.backgroundColor = [UIColor colorWithRed:0 green:0.5 blue:1 alpha:0.8];
    self.button.layer.cornerRadius = 25;
    self.button.layer.masksToBounds = YES;
    [self.button setTitle:@"LOG" forState:UIControlStateNormal];
    [self.button setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.button.titleLabel.font = [UIFont boldSystemFontOfSize:12];
    self.button.userInteractionEnabled = YES; // Ensure button catches touches
    [self.button addTarget:self action:@selector(buttonTapped) forControlEvents:UIControlEventTouchUpInside];
    
    // Add pan gesture
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    [self.button addGestureRecognizer:pan];
    
    // Add to root view instead of window directly (safer)
    [self.window.rootViewController.view addSubview:self.button];
    
    NSLog(@"[CryptoMonitor] Floating button created successfully");
}

- (void)handlePan:(UIPanGestureRecognizer *)p {
    UIView *btn = p.view;
    CGPoint translation = [p translationInView:self.window.rootViewController.view];
    CGPoint newCenter = CGPointMake(btn.center.x + translation.x, btn.center.y + translation.y);
    
    // Keep button within screen bounds
    CGRect bounds = self.window.bounds;
    CGFloat halfWidth = btn.frame.size.width / 2;
    CGFloat halfHeight = btn.frame.size.height / 2;
    
    newCenter.x = MAX(halfWidth, MIN(bounds.size.width - halfWidth, newCenter.x));
    newCenter.y = MAX(halfHeight + 50, MIN(bounds.size.height - halfHeight - 50, newCenter.y)); // 50pt padding for safe areas
    
    btn.center = newCenter;
    [p setTranslation:CGPointZero inView:self.window.rootViewController.view];
}

- (void)buttonTapped {
    LogViewController *vc = [[LogViewController alloc] init];
    vc.modalPresentationStyle = UIModalPresentationFullScreen;
    UIViewController *rootVC = self.window.rootViewController;
    
    // Make sure we can present
    if (rootVC.presentedViewController) {
        [rootVC dismissViewControllerAnimated:NO completion:^{
            [rootVC presentViewController:vc animated:YES completion:nil];
        }];
    } else {
        [rootVC presentViewController:vc animated:YES completion:nil];
    }
}

@end


// MARK: - Tweak Entry

%ctor {
    NSLog(@"[CryptoMonitor] Loaded");
    // Initialize Floating UI with delay to ensure app UI is ready
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[FloatingController sharedInstance] setup];
    });
}

