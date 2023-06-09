@extends("layouts.front")

@section("css")
@endsection

@section("content")
    <div class="row">
        <div class="col-md-12">
            <x-bootstrap.card>
                <x-slot:header>
                    Giriş Yap
                </x-slot:header>
                <x-slot:body>
                    <form action="{{ route('login') }}" method="post" class="login-form">
                        @csrf
                        <div class="row">
                            <div class="col-md-12 mt-2">
                                <input type="text" name="email" id="email" class="form-control" placeholder="Email">
                            </div>
                            <div class="col-md-12 mt-2">
                                <input type="password" name="password" id="password" class="form-control"
                                       placeholder="Parolanız">
                                <hr class="my-4">
                            </div>
                            <div class="col-md-12 my-3 social-media-register">
                                <div class="d-flex justify-content-center">
                                    <a href=""><i class="fa fa-google fa-2x me-3"></i></a>
                                    <a href=""><i class="fa fa-facebook fa-2x me-3"></i></a>
                                    <a href=""><i class="fa fa-twitter fa-2x me-3"></i></a>
                                    <a href=""><i class="fa fa-github fa-2x"></i></a>
                                </div>
                                <hr class="my-4">

                            </div>
                            <div class="col-md-12 ">
                                <button type="submit" class="btn btn-success w-100">
                                    Giriş Yap
                                </button>
                            </div>
                        </div>
                    </form>
                </x-slot:body>
            </x-bootstrap.card>
        </div>
    </div>
@endsection

@section("js")
@endsection