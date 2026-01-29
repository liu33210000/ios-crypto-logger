#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <objc/runtime.h>

// MARK: - Logger Interface

@interface LogManager : NSObject
+ (instancetype)sharedInstance;
- (void)log:(NSString *)format, ...;
- (NSString *)getLogPath;
- (NSString *)getLogContent;
- (void)clearLogs;
@end

@implementation LogManager {
    NSFileHandle *_fileHandle;
    NSString *_logPath;
    NSLock *_lock;
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
        _lock = [[NSLock alloc] init];
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *docsDir = [paths firstObject];
        _logPath = [docsDir stringByAppendingPathComponent:@"crypto_monitor.log"];
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:_logPath]) {
            [@"" writeToFile:_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        _fileHandle = [NSFileHandle fileHandleForWritingAtPath:_logPath];
        [_fileHandle seekToEndOfFile];
    }
    return self;
}

- (void)log:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *logLine = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    NSString *timestampedLog = [NSString stringWithFormat:@"[%@] %@\n", [NSDate date], logLine];
    
    [_lock lock];
    NSData *data = [timestampedLog dataUsingEncoding:NSUTF8StringEncoding];
    [_fileHandle writeData:data];
    // In a real high-perf scenario, might want to buffer this, but for now flush to ensure safety
    // [_fileHandle synchronizeFile]; 
    [_lock unlock];
    
    NSLog(@"[CryptoMonitor] %@", logLine);
}

- (NSString *)getLogPath {
    return _logPath;
}

- (NSString *)getLogContent {
    [_lock lock];
    NSString *content = [NSString stringWithContentsOfFile:_logPath encoding:NSUTF8StringEncoding error:nil];
    [_lock unlock];
    return content;
}

- (void)clearLogs {
    [_lock lock];
    [@"" writeToFile:_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [_fileHandle closeFile];
    _fileHandle = [NSFileHandle fileHandleForWritingAtPath:_logPath];
    [_lock unlock];
}

@end

// MARK: - Utilities

NSString *DataToHex(const void *data, size_t length) {
    if (!data || length == 0) return @"";
    const unsigned char *buffer = (const unsigned char *)data;
    NSMutableString *hexString = [NSMutableString stringWithCapacity:length * 2];
    for (size_t i = 0; i < length; i++) {
        [hexString appendFormat:@"%02x", buffer[i]];
    }
    return hexString;
}

// MARK: - Hooks

// 1. MD5
%hookf(unsigned char *, CC_MD5, const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = %orig(data, len, md);
    if (len > 0) {
        [[LogManager sharedInstance] log:@"[MD5] Input: %@ -> Hash: %@", DataToHex(data, len), DataToHex(result, CC_MD5_DIGEST_LENGTH)];
    }
    return result;
}

// 2. SHA256
%hookf(unsigned char *, CC_SHA256, const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = %orig(data, len, md);
    if (len > 0) {
        [[LogManager sharedInstance] log:@"[SHA256] Input: %@ -> Hash: %@", DataToHex(data, len), DataToHex(result, CC_SHA256_DIGEST_LENGTH)];
    }
    return result;
}

// 3. CCCrypt (AES/DES etc)
%hookf(CCCryptorStatus, CCCrypt, CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
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

// 4. Base64
%hook NSData
- (id)initWithBase64EncodedString:(NSString *)base64String options:(NSDataBase64DecodingOptions)options {
    id result = %orig;
    if (result) {
        [[LogManager sharedInstance] log:@"[Base64Decode] In: %@ -> Out: %@", base64String, DataToHex([result bytes], [result length])];
    }
    return result;
}

- (NSString *)base64EncodedStringWithOptions:(NSDataBase64EncodingOptions)options {
    NSString *result = %orig;
    if (self.length > 0) {
        [[LogManager sharedInstance] log:@"[Base64Encode] In: %@ -> Out: %@", DataToHex([self bytes], [self length]), result];
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
    
    [self refreshLogs];
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
    // Only capture touches on the subviews (the button), let others pass through
    for (UIView *view in self.subviews) {
        if (!view.hidden && view.userInteractionEnabled && [view pointInside:[self convertPoint:point toView:view] withEvent:event]) {
            return YES;
        }
    }
    return NO;
}
@end

@interface FloatingController : NSObject
@property (nonatomic, strong) FloatingWindow *window;
@property (nonatomic, strong) UIButton *button;
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
    dispatch_async(dispatch_get_main_queue(), ^{
        self.window = [[FloatingWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        self.window.windowLevel = UIWindowLevelAlert + 100; // Above almost everything
        self.window.backgroundColor = [UIColor clearColor];
        self.window.rootViewController = [[UIViewController alloc] init];
        self.window.hidden = NO;
        
        self.button = [UIButton buttonWithType:UIButtonTypeCustom];
        self.button.frame = CGRectMake(20, 100, 50, 50);
        self.button.backgroundColor = [UIColor colorWithRed:0 green:0.5 blue:1 alpha:0.8];
        self.button.layer.cornerRadius = 25;
        self.button.layer.masksToBounds = YES;
        [self.button setTitle:@"LOG" forState:UIControlStateNormal];
        [self.button addTarget:self action:@selector(buttonTapped) forControlEvents:UIControlEventTouchUpInside];
        
        // Add pan gesture
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
        [self.button addGestureRecognizer:pan];
        
        [self.window addSubview:self.button];
    });
}

- (void)handlePan:(UIPanGestureRecognizer *)p {
    UIView *btn = p.view;
    CGPoint translation = [p translationInView:self.window];
    btn.center = CGPointMake(btn.center.x + translation.x, btn.center.y + translation.y);
    [p setTranslation:CGPointZero inView:self.window];
}

- (void)buttonTapped {
    LogViewController *vc = [[LogViewController alloc] init];
    vc.modalPresentationStyle = UIModalPresentationFullScreen;
    [[self.window rootViewController] presentViewController:vc animated:YES completion:nil];
}

@end


// MARK: - Tweak Entry

%ctor {
    NSLog(@"[CryptoMonitor] Loaded");
    // Initialize Floating UI with delay to ensure KeyWindow is ready-ish
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[FloatingController sharedInstance] setup];
    });
}
