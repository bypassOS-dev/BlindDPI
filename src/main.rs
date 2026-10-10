//=========LINUX=================
#[cfg(target_os = "linux")]
mod linux;
//===============================
//==========WINDOWS==============
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::like_main as backend;
//===============================
//==========GENERAL==============
use run_blinddpi::run_blinddpi;
use eframe::egui;
use tokio_util::sync::CancellationToken;

mod run_blinddpi;
mod helper_functions;
pub mod send_packet;
//===============================


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>>{
    let option = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([320.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "BlindDPI", 
        option, 
        Box::new(|_cc| Ok(Box::new(MyApp::default())))
    ).unwrap();

    Ok(())
}

struct MyApp{
    is_running: bool,
    show_settings: bool,
    split_tunneling: bool,
    cancel_token: Option<CancellationToken>
}

impl Default for MyApp {
    fn default() -> Self {
        Self { 
            is_running: false,
            show_settings: false,
            split_tunneling: false,
            cancel_token: None,
        }
    }
}

impl eframe::App for MyApp{
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.show_settings {
                ui.vertical_centered(|ui| {
                    ui.add_space(10.0);
                    ui.heading(egui::RichText::new("BlindDPI Settings"));
                    ui.add_space(10.0);
                });

                ui.checkbox(&mut self.split_tunneling, "Split tunneling");

                ui.add_space(300.0);

                ui.vertical_centered(|ui| {
                    if ui.button(egui::RichText::new("Back").size(18.0)).clicked() {
                        self.show_settings = !self.show_settings;
                    }
                });
            } else {
                //====== Settings ======================
                ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                    if ui.button(egui::RichText::new("⚙").size(20.0)).clicked() {
                    self.show_settings = !self.show_settings;
                    }
                });
                // ======================================
                //============ Main =====================   
                ui.vertical_centered(|ui| {
                    // ======= Header ==========
                    ui.heading(egui::RichText::new("BlindDPI"). size(30.0));
                    // =========================

                    ui.add_space(75.0);

                    // ========== Button ===========
                    let (btn_text, btn_bg_color) = if self.is_running {
                        ("Stop", egui::Color32::from_rgb(180, 50, 50))
                    } else {
                        ("Start", egui::Color32::from_rgb(40, 140, 60)) 
                    };

                    let rich_btn_text = egui::RichText::new(btn_text)
                        .size(22.0)
                        .color(egui::Color32::WHITE);
                    let button = egui::Button::new(rich_btn_text)
                        .fill(btn_bg_color)
                        .rounding(60.0);

                    if ui.add_sized([120.0, 120.0], button).clicked() {
                        if !self.is_running {
                            let token = CancellationToken::new();

                            let token_for_backend = token.clone();

                            self.cancel_token = Some(token);

                            let split_tunneling_bool = self.split_tunneling;
                            tokio::spawn(async move {
                                run_blinddpi(token_for_backend, &split_tunneling_bool).await;
                            });
                        } else {
                            if let Some(token) = self.cancel_token.take() {
                                token.cancel();
                            }
                        }
                        
                        self.is_running = !self.is_running;
                    }
                    //==============================

                    ui.add_space(5.0);

                    //======= Status ===========
                    let (status_text, status_color) = if self.is_running {
                        ("BlindDPI is running", egui::Color32::GREEN)
                    } else {
                        ("BlindDPI is stopped", egui::Color32::RED)
                    };
                    
                    ui.label(
                        egui::RichText::new(status_text)
                        .size(20.0)
                        .color(status_color)
                    );
                });
            }
        });
    }
}