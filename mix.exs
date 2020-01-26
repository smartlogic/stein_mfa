defmodule SteinMfa.MixProject do
  use Mix.Project

  def project do
    [
      app: :stein_mfa,
      version: "0.1.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:stein, "~> 0.5.1"},

      {:pot, "~> 0.10.2"},

      {:credo, "~> 1.1", only: [:dev, :test]}
    ]
  end
end
