<?php

namespace App\Http\Controllers\Admin;

use App\Models\Admin;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\Verified;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Auth\Events\Registered;
use App\Providers\RouteServiceProvider;
use App\Http\Requests\Auth\LoginRequest;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Validation\Rules\Password;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use Illuminate\Foundation\Auth\EmailVerificationRequest;

class AuthController extends Controller
{
    public function showRegisterForm()
    {
        return view('admin.auth.register');
    }

    public function submitRegisterForm(Request $request)
    {
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:admins'],
            'password' => ['required', 'confirmed', 'min:8'],
        ]);

        $admin = Admin::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        event(new Registered($admin));

        Auth::guard('admin')->login($admin);

        return redirect(RouteServiceProvider::ADMIN_HOME);
    }

    public function showLoginForm()
    {
        return view('admin.auth.login');
    }

    public function submitLoginForm(LoginRequest $request)
    {
        $request->ensureIsNotRateLimited();
        if (!Auth::guard('admin')->attempt($request->only('email', 'password'), $request->filled('remember'))) {
            RateLimiter::hit($request->throttleKey());
            throw ValidationException::withMessages([
                'email' => __('auth.failed'),
            ]);
        }
        RateLimiter::clear($request->throttleKey());
        $request->session()->regenerate();
        return redirect(RouteServiceProvider::ADMIN_HOME);
    }

    public function showForgetPasswordForm()
    {
        return view('admin.auth.forgot-password');
    }

    public function submitForgetPasswordForm(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
        ]);

        $status = $this->broker()->sendResetLink($request->only('email'));

        return $status == Password::RESET_LINK_SENT
            ? back()->with('status', __($status))
            : back()->withInput($request->only('email'))
            ->withErrors(['email' => __($status)]);
    }

    public function getResetPasswordForm(Request $request)
    {
        return view('admin.auth.reset-password', ['request' => $request]);
    }

    public function submitResetPasswordForm(Request $request)
    {
        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|string|confirmed|min:8',
        ]);

        $status = $this->broker()->reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user) use ($request) {
                $user->forceFill([
                    'password' => Hash::make($request->password),
                    'remember_token' => Str::random(60),
                ])->save();

                event(new PasswordReset($user));
            }
        );

        return $status == Password::PASSWORD_RESET
            ? redirect()->route('admin.login')->with('status', __($status))
            : back()->withInput($request->only('email'))
            ->withErrors(['email' => __($status)]);
    }

    public function showVerificationNoticePage(Request $request)
    {
        return $request->user('admin')->hasVerifiedEmail()
            ? redirect()->intended(RouteServiceProvider::ADMIN_HOME)
            : view('admin.auth.verify-email');
    }

    public function verifyEmail(EmailVerificationRequest $request)
    {
        if ($request->user('admin')->hasVerifiedEmail()) {
            return redirect()->intended(RouteServiceProvider::ADMIN_HOME . '?verified=1');
        }

        if ($request->user('admin')->markEmailAsVerified()) {
            event(new Verified($request->user('admin')));
        }

        return redirect()->intended(RouteServiceProvider::ADMIN_HOME . '?verified=1');
    }

    public function sendVerificationNotification(Request $request)
    {
        if ($request->user('admin')->hasVerifiedEmail()) {
            return redirect()->intended(RouteServiceProvider::ADMIN_HOME);
        }

        $request->user('admin')->sendEmailVerificationNotification();

        return back()->with('status', 'verification-link-sent');
    }

    public function submitLogoutForm(Request $request)
    {
        Auth::guard('admin')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return redirect('/');
    }

    protected function broker()
    {
        return Password::broker('admins');
    }
}