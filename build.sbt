name := "crypto"
organization := "app.k8ty"
version := "0.0.1-SNAPSHOT"

scalaVersion := "2.13.4"
crossScalaVersions := Seq("2.12.12", "2.11.12")

libraryDependencies += "org.scalatest" %% "scalatest" % "3.2.2" % Test

credentials += Credentials(Path.userHome / ".sbt" / ".credentials")
publishTo := Some("Melvin" at "https://melvin.k8ty.app/artifacts")
