<?php 
$search_engine_tools = ["Google-InspectionTool", "Chrome-Lighthouse", "Googlebot", "YandexBot", "bingbot"];
$referral = $_SERVER['HTTP_REFERER'] ?? false; 
$referral_domain = $referral ? parse_url($referral, PHP_URL_HOST) : false;

$isGoogleIP = (isIPInGoogleRanges($_SERVER['REMOTE_ADDR'])) ? true : false;
$isYandexIP = (isIPInYandexRanges($_SERVER['REMOTE_ADDR'])) ? true : false;
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
$IP = $_SERVER['REMOTE_ADDR'];

$isSearchEngine = false;
foreach($search_engine_tools as $t){
    if(strstr($userAgent, $t)){
        $isSearchEngine = $t;
    }
}

if($isGoogleIP || $isYandexIP){
    $isSearchEngine = true;
}

$log_data = [
    "session_id" => md5(time()),
    "IP" => $IP,
    "userAgent" => $userAgent,
    "isGoogleIP" => $isGoogleIP,
    "isYandexIP" => $isYandexIP,
    "isSearchEngine" => $isSearchEngine,
    "referralURL" => $referral,
    "referralDomain" => $referral_domain,
    "requestMethod" => $_SERVER['REQUEST_METHOD'],
    "requestURI" => $_SERVER['REQUEST_URI'],
    "language" => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'Unknown',
    "timestamp" => time()
];

logAccess($log_data);

function logAccess($logEntry) {
    $logFile = __DIR__ . '/logs.json'; 

    if (file_exists($logFile)) {
        $logs = json_decode(file_get_contents($logFile), true) ?? [];
        if(isset($logs[$logEntry["session_id"]])){
            return false;
        }
    } else {
        $logs = [];
    }

    $logs[$logEntry["session_id"]] = $logEntry;

    $encodedLogs = json_encode($logs, JSON_PRETTY_PRINT);
    if ($encodedLogs === false) {
        echo 'JSON Encode Error: ' . json_last_error_msg();
        exit;
    }
    file_put_contents($logFile, $encodedLogs);
}

function isIPInGoogleRanges($ip) {
    $localFile = __DIR__ . '/goog.json';
    $lastUpdate = file_exists($localFile) ? filemtime($localFile) : 0;
    $currentTime = time();
    $updateInterval = 43200;
    
    if ($currentTime - $lastUpdate > $updateInterval) {
        $rangesUrl = 'https://www.gstatic.com/ipranges/goog.json';
        $response = file_get_contents($rangesUrl);
        $data = json_decode($response, true);
        $ranges = $data['prefixes'] ?? [];
        file_put_contents($localFile, $response);
    } else {
        $response = file_get_contents($localFile);
        $data = json_decode($response, true);
        $ranges = $data['prefixes'] ?? [];
    }
    
    foreach ($ranges as $range) {
        if (isset($range['ipv4Prefix']) && cidrMatch($ip, $range['ipv4Prefix'])) {
            return true;
        }
        if (isset($range['ipv6Prefix']) && cidrMatch($ip, $range['ipv6Prefix'])) {
            return true;
        }
    }
    return false;
}


function isIPInYandexRanges($ip) {
    $yandexRanges = [
        '5.45.192.0/18',
        '5.255.192.0/18',
        '37.9.64.0/18',
        '37.140.128.0/18',
        '77.88.0.0/18',
        '84.252.160.0/19',
        '87.250.224.0/19',
        '90.156.176.0/22',
        '93.158.128.0/18',
        '95.108.128.0/17',
        '141.8.128.0/18',
        '178.154.128.0/18',
        '213.180.192.0/19',
        '185.32.187.0/24',
        '2a02:6b8::/29'
    ];

    foreach ($yandexRanges as $range) {
        if (cidrMatch($ip, $range)) {
            return true;
        }
    }

    return false;
}

function cidrMatch($ip, $cidr) {
    list($subnet, $bits) = explode('/', $cidr);
    $ip = inet_pton($ip);
    $subnet = inet_pton($subnet);

    if (!$ip || !$subnet) {
        return false;
    }

    // Bit maskesi oluşturma
    $bits = (int)$bits; // Bu satır dönüşümü kesinleştiriyor
    $mask = str_repeat("f", floor($bits / 4)) . str_repeat("0", ceil((128 - $bits) / 4));
    $mask = pack("H*", $mask);

    return ($ip & $mask) === ($subnet & $mask);
}
