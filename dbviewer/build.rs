use cxx_qt_build::{CxxQtBuilder, QmlModule};

fn main() {
    CxxQtBuilder::new_qml_module(
        QmlModule::new("MC.DbViewer").qml_file("qml/main.qml"),
    )
    .qt_module("Quick")
    .qt_module("QuickControls2")
    .files(["src/model.rs"])
    .build();
}
