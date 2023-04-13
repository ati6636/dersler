<h1>Doğrulama Emaili</h1>

<p>
    Merhaba {{ $user->name }}, Hoş Geldiniz
</p>

<p>
    Lütfen aşağıdaki linke tıklayarak mailinizi doğrulayınız. <br>
</p>

<a href="{{ route('verify-token', ['token' => $token]) }}">
    Mailimi Doğrula
</a>