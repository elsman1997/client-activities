<?php

// Load environment variables
(function ($path) {
    if (!is_file($path)) return;
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;

        $parts = explode('=', $line, 2);
        if (count($parts) !== 2) continue;

        $name = trim($parts[0]);
        $value = trim($parts[1]);

        // strip optional surrounding quotes
        if ((strlen($value) >= 2) && (
            ($value[0] === '"' && substr($value, -1) === '"') ||
            ($value[0] === "'" && substr($value, -1) === "'")
        )) {
            $value = substr($value, 1, -1);
        }

        putenv("$name=$value");
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
    }
})(__DIR__ . '/.env');

session_start();

// To prevent long operations from timing out
ignore_user_abort(true);
set_time_limit(0);
ini_set('display_errors', '0');

// Check if user is logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';

        if ($username === ($_ENV['ADMIN_USERNAME'] ?? '') && $password === ($_ENV['ADMIN_PASSWORD'] ?? '')) {
            $_SESSION['logged_in'] = true;
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $error = 'Invalid credentials';
        }
    }
?>
    <!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Lightsail Activities Monitor - Login</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {
                background: linear-gradient(135deg, #232F3E, #146EB4);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .login-card {
                background: white;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
                padding: 40px;
                max-width: 400px;
                width: 100%;
            }

            .login-header {
                text-align: center;
                margin-bottom: 30px;
                color: #232F3E;
            }

            .btn-login {
                background-color: #FF9900;
                border-color: #FF9900;
                width: 100%;
            }

            .btn-login:hover {
                background-color: #e88a00;
                border-color: #e88a00;
            }
        </style>
    </head>

    <body>
        <div class="login-card">
            <div class="login-header">
                <i class="fas fa-server fa-3x mb-3"></i>
                <h3>Lightsail Activities Monitor</h3>
                <p class="text-muted">Monitor Client Session Activities</p>
            </div>

            <?php if (isset($error)): ?>
                <div class="alert alert-danger" role="alert">
                    <i class="fas fa-exclamation-triangle me-2"></i><?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <form method="POST">
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-user"></i></span>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                </div>
                <button type="submit" name="login" class="btn btn-primary btn-login">
                    <i class="fas fa-sign-in-alt me-2"></i>Login
                </button>
            </form>
        </div>
    </body>

    </html>
<?php
    exit;
}

// Handle AJAX requests for authenticated users
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');

    switch ($_POST['action']) {
        case 'get_activities':
            $instance_name = $_POST['instance_name'] ?? '';
            $working_dir = $_POST['working_dir'] ?? '/var/www/html/bexel26';
            echo json_encode(getClientActivities($instance_name, $working_dir));
            break;

        case 'logout':
            session_destroy();
            echo json_encode(['success' => true]);
            break;
    }
    exit;
}

// Function to get Lightsail instance IP
function get_lightsail_instance_ip($instance_name)
{
    $aws_access_key = $_ENV['AWS_ACCESS_KEY_ID'] ?? '';
    $aws_secret_key = $_ENV['AWS_SECRET_ACCESS_KEY'] ?? '';
    $aws_region = $_ENV['AWS_REGION'] ?? 'us-east-1';

    if (empty($aws_access_key) || empty($aws_secret_key)) {
        return ['success' => false, 'error' => 'AWS credentials not configured'];
    }

    $cmd = sprintf(
        "AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_REGION=%s aws lightsail get-instance --instance-name %s --query 'instance.publicIpAddress' --output text 2>&1",
        escapeshellarg($aws_access_key),
        escapeshellarg($aws_secret_key),
        escapeshellarg($aws_region),
        escapeshellarg($instance_name)
    );

    $ip = shell_exec($cmd);
    return trim($ip);
}

// Function to get client activities (calls shell script and reads JSON)
function getClientActivities($instance_name, $working_dir)
{
    $logs = [];
    $append = function ($msg) use (&$logs) {
        $logs[] = '[' . date('H:i:s') . '] ' . $msg;
    };

    try {
        $append("Running check-client-activities.sh for instance: $instance_name");

        $scriptPath = __DIR__ . '/check-client-activities.sh';
        $cmd = escapeshellcmd($scriptPath) . ' ' . escapeshellarg($instance_name);

        if (!empty($working_dir)) {
            $cmd .= ' ' . escapeshellarg($working_dir);
        }

        // run as www-data
        $output = shell_exec("sudo -u www-data /var/www/html/automation/client-activities/check-client-activities.sh " . escapeshellarg($instance_name) . " " . escapeshellarg($working_dir) . " 2>&1");

        $append("Script output: " . trim($output));

        $jsonFile = __DIR__ . '/activities.json';
        if (!file_exists($jsonFile)) {
            return ['success' => false, 'error' => 'activities.json not found after script run', 'logs' => $logs];
        }

        $data = json_decode(file_get_contents($jsonFile), true);
        if (!is_array($data)) {
            return ['success' => false, 'error' => 'Invalid JSON in activities.json', 'logs' => $logs];
        }

        // sort by last_seen_min ascending (most recent first)
        usort($data, function ($a, $b) {
            return $a['last_seen_min'] <=> $b['last_seen_min'];
        });

        return [
            'success' => true,
            'activities' => $data,
            'instance_name' => $instance_name,
            'working_dir' => $working_dir,
            'logs' => $logs
        ];
    } catch (Exception $e) {
        $append('Error: ' . $e->getMessage());
        return ['success' => false, 'error' => 'Operation failed: ' . $e->getMessage(), 'logs' => $logs];
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lightsail Client Activities Monitor</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome@6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/alertifyjs@1.14.0/build/css/alertify.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/alertifyjs@1.14.0/build/css/themes/bootstrap.min.css">
    <style>
        * {
            box-sizing: border-box;
        }

        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        .navbar-brand {
            font-weight: bold;
            color: #EFEFEF !important;
        }

        .card {
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            border: none;
        }

        .card-header {
            background-color: #232F3E;
            color: white;
            border-radius: 10px 10px 0 0 !important;
            padding: 15px 20px;
            font-weight: 600;
        }

        .btn-primary {
            background-color: #FF9900;
            border-color: #FF9900;
        }

        .btn-primary:hover {
            background-color: #e88a00;
            border-color: #e88a00;
        }

        .activity-log {
            height: 300px;
            overflow-y: auto;
            background-color: #2d3748;
            color: #cbd5e0;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
        }

        .log-info {
            color: #68d391;
        }

        .log-warning {
            color: #faf089;
        }

        .log-error {
            color: #fc8181;
        }

        .log-success {
            color: #68d391;
            font-weight: bold;
        }

        .spinner-border-sm {
            width: 1rem;
            height: 1rem;
        }

        .user-info {
            color: #FF9900;
            font-weight: 500;
        }

        .activity-table {
            font-size: 0.9rem;
        }

        .activity-table th {
            background-color: #232F3E;
            color: white;
        }

        .recent-activity {
            background-color: #e8f5e9;
        }

        .old-activity {
            opacity: 0.7;
        }
    </style>
</head>

<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fas fa-server me-2"></i>Lightsail Activities Monitor
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text user-info me-3">
                    <i class="fas fa-user me-1"></i>Welcome, Admin
                </span>
                <button id="logoutBtn" class="btn btn-outline-light btn-sm">
                    <i class="fas fa-sign-out-alt me-1"></i>Logout
                </button>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-cog me-2"></i>Configuration
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="instanceName" class="form-label">Instance Name:</label>
                                    <input type="text" class="form-control" id="instanceName" placeholder="Enter instance name (e.g., TUV-Rheinland-ksa)">
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="workingDir" class="form-label">Working Directory:</label>
                                    <input type="text" class="form-control" id="workingDir" value="/var/www/html/bexel26" placeholder="Enter working directory">
                                </div>
                            </div>
                        </div>
                        <div class="row mt-3">
                            <div class="col-md-12 text-center">
                                <button id="getActivitiesBtn" class="btn btn-primary btn-lg">
                                    <i class="fas fa-sync-alt me-2"></i>Get Client Activities
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-tasks me-2"></i>Operation Log
                    </div>
                    <div class="card-body">
                        <div id="operationLog" class="activity-log">
                            <div class="log-info">System ready. Enter instance name and click "Get Client Activities".</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span><i class="fas fa-users me-2"></i>Client Activities</span>
                        <span id="resultsCount" class="badge bg-primary">0 results</span>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped table-hover activity-table">
                                <thead>
                                    <tr>
                                        <th>Email</th>
                                        <th>Name</th>
                                        <th>Last Seen (minutes ago)</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody id="activitiesTable">
                                    <tr>
                                        <td colspan="4" class="text-center text-muted">No data available</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="bg-dark text-white text-center py-3 mt-4">
        <p class="mb-0">Lightsail Client Activities Monitor © <span id="year"></span> | AWS Lightsail Session Monitoring</p>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/alertifyjs@1.14.0/build/alertify.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const instanceName = document.getElementById('instanceName');
            const workingDir = document.getElementById('workingDir');
            const getActivitiesBtn = document.getElementById('getActivitiesBtn');
            const operationLog = document.getElementById('operationLog');
            const activitiesTable = document.getElementById('activitiesTable');
            const resultsCount = document.getElementById('resultsCount');
            const logoutBtn = document.getElementById('logoutBtn');

            alertify.set('notifier', 'position', 'top-right');
            document.getElementById('year').textContent = new Date().getFullYear();

            function logMessage(message, type = 'info') {
                const logEntry = document.createElement('div');
                logEntry.className = `log-${type}`;
                logEntry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
                operationLog.appendChild(logEntry);
                operationLog.scrollTop = operationLog.scrollHeight;
            }

            function makeRequest(data, onSuccess, onError) {
                fetch(window.location.href, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        body: new URLSearchParams(data)
                    })
                    .then(async (response) => {
                        const contentType = response.headers.get('content-type') || '';
                        const text = await response.text();
                        if (!response.ok) {
                            throw new Error(`HTTP ${response.status} ${response.statusText}`);
                        }
                        if (!contentType.includes('application/json')) {
                            throw new Error(`Non-JSON response: ${text.slice(0, 160)}`);
                        }
                        let json;
                        try {
                            json = JSON.parse(text);
                        } catch (e) {
                            throw new Error(`Invalid JSON: ${text.slice(0, 160)}`);
                        }
                        return json;
                    })
                    .then(onSuccess)
                    .catch(error => {
                        logMessage('Request failed: ' + error.message, 'error');
                        alertify.error('Request failed: ' + error.message);
                        if (typeof onError === 'function') onError(error);
                    });
            }

            function displayActivities(activities) {
                if (activities.length === 0) {
                    activitiesTable.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No activities found</td></tr>';
                    resultsCount.textContent = '0 results';
                    return;
                }

                // Sort by last_seen_min (ascending - most recent first)
                activities.sort((a, b) => a.last_seen_min - b.last_seen_min);

                let html = '';
                activities.forEach(activity => {
                    const rowClass = activity.last_seen_min < 60 ? 'recent-activity' :
                        activity.last_seen_min > 240 ? 'old-activity' : '';

                    const status = activity.last_seen_min < 30 ? '<span class="badge bg-success">Active</span>' :
                        activity.last_seen_min < 120 ? '<span class="badge bg-warning">Recent</span>' :
                        '<span class="badge bg-secondary">Inactive</span>';

                    html += `
                        <tr class="${rowClass}">
                            <td>${activity.email}</td>
                            <td>${activity.name}</td>
                            <td>${activity.last_seen_min}</td>
                            <td>${status}</td>
                        </tr>
                    `;
                });

                activitiesTable.innerHTML = html;
                resultsCount.textContent = `${activities.length} results`;
            }

            getActivitiesBtn.addEventListener('click', function() {
                const instance = instanceName.value.trim();
                const wd = workingDir.value.trim() || '/var/www/html/bexel26';

                if (!instance) {
                    alertify.error('Please enter an instance name');
                    return;
                }

                operationLog.innerHTML = '';
                activitiesTable.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Loading...</td></tr>';
                resultsCount.textContent = '0 results';

                getActivitiesBtn.disabled = true;
                getActivitiesBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';

                logMessage(`Getting activities for instance: ${instance}`);
                logMessage(`Using working directory: ${wd}`);

                makeRequest({
                    action: 'get_activities',
                    instance_name: instance,
                    working_dir: wd
                }, function(response) {
                    if (response.logs && Array.isArray(response.logs)) {
                        response.logs.forEach(l => logMessage(l, 'info'));
                    }

                    if (response.success) {
                        logMessage(`Successfully retrieved ${response.activities.length} activities`, 'success');
                        alertify.success(`Found ${response.activities.length} activities`);
                        displayActivities(response.activities);
                    } else {
                        logMessage('Error: ' + response.error, 'error');
                        alertify.error(response.error || 'Failed to get activities');
                        activitiesTable.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Error loading data</td></tr>';
                    }

                    getActivitiesBtn.disabled = false;
                    getActivitiesBtn.innerHTML = '<i class="fas fa-sync-alt me-2"></i>Get Client Activities';
                }, function() {
                    getActivitiesBtn.disabled = false;
                    getActivitiesBtn.innerHTML = '<i class="fas fa-sync-alt me-2"></i>Get Client Activities';
                });
            });

            logoutBtn.addEventListener('click', function() {
                alertify.confirm('Confirm logout', 'Are you sure you want to logout?',
                    () => {
                        makeRequest({
                            action: 'logout'
                        }, function(response) {
                            if (response.success) {
                                window.location.reload();
                            }
                        });
                    },
                    () => {}
                );
            });

            logMessage('Lightsail Activities Monitor loaded successfully.', 'success');
        });
    </script>
</body>

</html>
