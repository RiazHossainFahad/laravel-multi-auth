<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Admin\AuthController;

Route::namespace('Admin')->prefix('admin')->as('admin.')->group(function () {
    Route::get('/register', [AuthController::class, 'showRegisterForm'])
        ->middleware('guest:admin')
        ->name('register');

    Route::post('/register', [AuthController::class, 'submitRegisterForm'])
        ->middleware('guest:admin')->name('register.post');

    Route::get('/login', [AuthController::class, 'showLoginForm'])
        ->middleware('guest:admin')
        ->name('login');

    Route::post('/login', [AuthController::class, 'submitLoginForm'])
        ->middleware('guest:admin')
        ->name('login.post');

    Route::get('/forgot-password', [AuthController::class, 'showForgetPasswordForm'])
        ->middleware('guest:admin')
        ->name('password.request');

    Route::post('/forgot-password', [AuthController::class, 'submitForgetPasswordForm'])
        ->middleware('guest:admin')
        ->name('password.email');

    Route::get('/reset-password/{token}', [AuthController::class, 'getResetPasswordForm'])
        ->middleware('guest:admin')
        ->name('password.reset');

    Route::post('/reset-password', [AuthController::class, 'submitResetPasswordForm'])
        ->middleware('guest:admin')
        ->name('password.update');

    Route::get('/verify-email', [AuthController::class, 'showVerificationNoticePage'])
        ->middleware('auth:admin')
        ->name('verification.notice');

    Route::get('/verify-email/{id}/{hash}', [AuthController::class, 'verifyEmail'])
        ->middleware(['auth:admin', 'signed', 'throttle:6,1'])
        ->name('verification.verify');

    Route::post('/email/verification-notification', [AuthController::class, 'sendVerificationNotification'])
        ->middleware(['auth:admin', 'throttle:6,1'])
        ->name('verification.send');

    Route::post('/logout', [AuthController::class, 'submitLogoutForm'])
        ->middleware('auth:admin')
        ->name('logout');
});